#!/usr/bin/env python3
import threading
import logging
import signal
import base64
import hashlib
from datetime import datetime, timezone
import time
from typing import Optional
import requests
from cachetools import TTLCache
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import json
from dotenv import load_dotenv
import os

# Default configuration values
CT_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
load_dotenv()

ELASTICSEARCH_HOSTS = os.getenv("ELASTICSEARCH_HOSTS", "http://localhost:9200")
ES_INDEX = "CertMonitor"
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
FETCH_INTERVAL = 60
BATCH_SIZE = 256
CACHE_MAXSIZE = 100000
CACHE_TTL = 3600
REQUEST_TIMEOUT = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

seen_certs = None  # Initialized in main
seen_lock = threading.Lock()
session = requests.Session()
stop_event = threading.Event()

def calculate_valid_days(not_before: datetime, not_after: datetime) -> int:
    return (not_after - not_before).days

def get_key_usage(cert: x509.Certificate) -> list:
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        usage = []
        if ku.digital_signature: usage.append("digital_signature")
        if ku.content_commitment: usage.append("content_commitment")
        if ku.key_encipherment: usage.append("key_encipherment")
        if ku.data_encipherment: usage.append("data_encipherment")
        if ku.key_agreement: usage.append("key_agreement")
        if ku.key_cert_sign: usage.append("key_cert_sign")
        if ku.crl_sign: usage.append("crl_sign")
        return usage
    except x509.ExtensionNotFound:
        return []

def get_extended_key_usage(cert: x509.Certificate) -> list:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        return [usage._name.lower() for usage in eku]
    except x509.ExtensionNotFound:
        return []

def load_log_list(url: str):
    try:
        resp = make_request(url, session, REQUEST_TIMEOUT)
        if not resp:
            raise Exception("Failed to fetch log list")
        data = resp.json()
    except Exception as e:
        logging.error(f"Could not load CT log list: {e}")
        return []
    logs = []
    log_entries = data.get("logs", data.get("operators", []))
    if "operators" in data:
        log_entries = []
        for operator in data["operators"]:
            log_entries.extend(operator.get("logs", []))
    now = datetime.now(timezone.utc)
    for log in log_entries:
        state = log.get("state", {})
        if "usable" not in state:
            continue
        interval = log.get("temporal_interval")
        if interval:
            try:
                start = datetime.fromisoformat(interval["start_inclusive"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(interval["end_exclusive"].replace("Z", "+00:00"))
                if now < start or now >= end:
                    continue
            except Exception as e:
                logging.warning(f"Cannot parse temporal_interval for {log.get('description')}: {e}")
        logs.append(log)
    logging.info(f"Loaded {len(logs)} CT logs to monitor.")
    return logs

def get_domains_from_cert(cert: x509.Certificate) -> list:
    domains = []
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if attr.value not in domains:
                domains.append(attr.value)
    except Exception:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for name in san.get_values_for_type(x509.DNSName):
            if name not in domains:
                domains.append(name)
    except x509.ExtensionNotFound:
        pass
    return domains

def get_issuer_name(cert: x509.Certificate) -> str:
    name = None
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if issuer_cn:
            name = issuer_cn[0].value
    except Exception:
        pass
    if not name:
        try:
            issuer_o = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if issuer_o:
                name = issuer_o[0].value
        except Exception:
            pass
    if not name:
        name = cert.issuer.rfc4514_string()
    return name

def make_request(url: str, session: requests.Session, timeout: int, max_retries: int = 3) -> Optional[requests.Response]:
    for attempt in range(max_retries):
        try:
            resp = session.get(url, timeout=timeout)
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after and retry_after.isdigit() else min(2 ** attempt, 60)
                logging.warning(f"429 Too Many Requests for {url}. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request to {url} failed: {e}. Attempt {attempt + 1}/{max_retries}")
            if attempt < max_retries - 1:
                time.sleep(min(2 ** attempt, 60))
            else:
                logging.error(f"Failed after {max_retries} attempts: {e}")
                return None

def parse_ct_entry(entry: dict, log_url: str, index: int) -> Optional[dict]:
    leaf_b64 = entry.get("leaf_input")
    extra_b64 = entry.get("extra_data")
    if not leaf_b64 or not extra_b64:
        return None
    
    try:
        leaf_bytes = base64.b64decode(leaf_b64)
        extra_bytes = base64.b64decode(extra_b64)
    except Exception as e:
        logging.warning(f"Base64 decoding error: {e}")
        return None
    
    if len(leaf_bytes) < 12:
        return None
    
    entry_type = int.from_bytes(leaf_bytes[10:12], byteorder='big')
    leaf_cert_bytes = None
    chain_cert_bytes = []
    
    try:
        if entry_type == 0:  # X509LogEntry
            if len(leaf_bytes) < 15:
                return None
            cert_len = int.from_bytes(leaf_bytes[12:15], byteorder='big')
            leaf_cert_bytes = leaf_bytes[15:15+cert_len]
            offset = 0
            while offset < len(extra_bytes):
                if offset + 3 > len(extra_bytes):
                    break
                cert_len = int.from_bytes(extra_bytes[offset:offset+3], byteorder='big')
                offset += 3
                if offset + cert_len > len(extra_bytes):
                    break
                cert_bytes = extra_bytes[offset:offset+cert_len]
                offset += cert_len
                if cert_bytes:
                    chain_cert_bytes.append(cert_bytes)
        elif entry_type == 1:  # PrecertLogEntry
            offset = 0
            if len(extra_bytes) < 3:
                return None
            precert_len = int.from_bytes(extra_bytes[offset:offset+3], byteorder='big')
            offset += 3
            if offset + precert_len > len(extra_bytes):
                return None
            leaf_cert_bytes = extra_bytes[offset:offset+precert_len]
            offset += precert_len
            while offset < len(extra_bytes):
                if offset + 3 > len(extra_bytes):
                    break
                cert_len = int.from_bytes(extra_bytes[offset:offset+3], byteorder='big')
                offset += 3
                if offset + cert_len > len(extra_bytes):
                    break
                cert_bytes = extra_bytes[offset:offset+cert_len]
                offset += cert_len
                if cert_bytes:
                    chain_cert_bytes.append(cert_bytes)
        else:
            return None
    except Exception as e:
        logging.error(f"Error parsing entry structure: {e}")
        return None
    
    try:
        cert = x509.load_der_x509_certificate(leaf_cert_bytes, default_backend())
    except Exception as e:
        logging.error(f"Certificate parse error: {e}")
        return None

    fingerprint = hashlib.sha256(leaf_cert_bytes).hexdigest().upper()
    with seen_lock:
        if fingerprint in seen_certs:
            return None
        seen_certs[fingerprint] = True

    not_before = cert.not_valid_before_utc.isoformat(timespec='milliseconds') + "Z"
    not_after = cert.not_valid_after_utc.isoformat(timespec='milliseconds') + "Z"
    current_time = datetime.now(timezone.utc).isoformat(timespec='milliseconds') + "Z"
    
    chain_summary = []
    for cbytes in chain_cert_bytes:
        try:
            chain_cert = x509.load_der_x509_certificate(cbytes, default_backend())
            cn = chain_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            chain_summary.append({
                "cn": cn[0].value if cn else chain_cert.subject.rfc4514_string(),
                "not_after": chain_cert.not_valid_after_utc.isoformat(timespec='milliseconds') + "Z"
            })
        except Exception:
            continue

    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [ad.access_location.value for ad in aia if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
        issuer_urls = [ad.access_location.value for ad in aia if ad.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS]
        ocsp_url = ocsp_urls[0] if ocsp_urls else None
        issuer_cert_url = issuer_urls[0] if issuer_urls else None
    except x509.ExtensionNotFound:
        ocsp_url = None
        issuer_cert_url = None

    try:
        crl_dps = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        crl_urls = [dp.full_name[0].value for dp in crl_dps if dp.full_name]
        crl_url = crl_urls[0] if crl_urls else None
    except x509.ExtensionNotFound:
        crl_url = None

    # Handle different public key types
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm = "rsa"
        key_size = public_key.key_size
        public_exponent = public_key.public_numbers().e
        curve_name = None
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        algorithm = "ec"
        key_size = public_key.key_size
        public_exponent = None
        curve_name = public_key.curve.name
    else:
        algorithm = "unknown"
        key_size = None
        public_exponent = None
        curve_name = None

    return {
        "log_url": log_url,
        "timestamp": int(time.time() * 1000),
        "type": "x509",
        "update_type": "X509LogEntry" if entry_type == 0 else "PrecertLogEntry",
        "fingerprint": fingerprint,
        "version": cert.version.value + 1,
        "serial_number": str(cert.serial_number),
        "signature_algorithm": f"{cert.signature_hash_algorithm.name}_{algorithm}",
        "issuer_cn": get_issuer_name(cert),
        "subject_cn": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else None,
        "validity": {
            "not_before": not_before,
            "not_after": not_after,
            "valid_days": calculate_valid_days(cert.not_valid_before_utc, cert.not_valid_after_utc)
        },
        "subject_public_key_info": {
            "algorithm": algorithm,
            "key_size_bits": key_size,
            "public_exponent": public_exponent,
            "curve_name": curve_name
        },
        "all_domains": get_domains_from_cert(cert),
        "ocsp_url": ocsp_url,
        "issuer_cert_url": issuer_cert_url,
        "crl_url": crl_url,
        "key_usage": get_key_usage(cert),
        "extended_key_usage": get_extended_key_usage(cert),
        "cert_index": index,
        "cert_link": f"{log_url}ct/v1/get-entries?start={index}&end={index}",
        "@timestamp": current_time,
        "seen": current_time,
        "source": {
            "url": log_url,
            "name": ""
        },
        "chain_summary": chain_summary
    }

def monitor_log(log_info: dict, ELASTICSEARCH_HOSTS: str, es_index: str, auth: Optional[tuple]):
    desc = log_info.get("description", "CT Log")
    url = log_info.get("url", "")
    if not url.endswith("/"):
        url += "/"
    
    sth_url = url + "ct/v1/get-sth"
    entriELASTICSEARCH_HOSTS = url + "ct/v1/get-entries"
    next_index = 0
    
    resp = make_request(sth_url, session, REQUEST_TIMEOUT)
    if resp:
        try:
            sth_data = resp.json()
            tree_size = int(sth_data.get("tree_size", 0))
            next_index = tree_size
            logging.info(f"Monitoring {desc}: starting at index {next_index}")
        except Exception as e:
            logging.error(f"Failed to initialize {desc}: {e}")
            return
    else:
        logging.error(f"Failed to fetch initial STH for {desc}")
        return

    while not stop_event.is_set():
        try:
            resp = make_request(sth_url, session, REQUEST_TIMEOUT)
            if not resp:
                current_size = next_index
            else:
                sth = resp.json()
                current_size = int(sth.get("tree_size", 0))

            if current_size < next_index:
                logging.warning(f"{desc}: tree size decreased, resetting index.")
                next_index = current_size
            
            if current_size > next_index:
                start = next_index
                end = min(current_size - 1, start + BATCH_SIZE - 1)
                
                while start <= end and not stop_event.is_set():
                    batch_url = f"{entriELASTICSEARCH_HOSTS}?start={start}&end={end}"
                    resp_entries = make_request(batch_url, session, REQUEST_TIMEOUT)
                    if not resp_entries:
                        start = end + 1
                        continue

                    try:
                        data = resp_entries.json()
                    except Exception as e:
                        logging.error(f"Failed to parse entries for {desc}: {e}")
                        start = end + 1
                        continue

                    entries = data.get("entries", [])
                    docs = []
                    for idx, entry in enumerate(entries, start=start):
                        cert_meta = parse_ct_entry(entry, url, idx)
                        if cert_meta:
                            cert_meta["source"]["name"] = desc
                            docs.append(cert_meta)

                    if docs:
                        bulk_lines = ""
                        for doc in docs:
                            meta = {"index": {"_index": es_index}}
                            bulk_lines += json.dumps(meta) + "\n"
                            bulk_lines += json.dumps(doc) + "\n"
                        for attempt in range(3):
                            try:
                                resp_es = requests.post(
                                    f"{ELASTICSEARCH_HOSTS}/_bulk",
                                    data=bulk_lines,
                                    headers={"Content-Type": "application/x-ndjson"},
                                    timeout=REQUEST_TIMEOUT,
                                    auth=auth
                                )
                                resp_es.raise_for_status()
                                result = resp_es.json()
                                if result.get("errors"):
                                    logging.error(f"{desc}: Bulk index errors reported.")
                                break
                            except requests.exceptions.RequestException as e:
                                logging.warning(f"ES Attempt {attempt+1} failed: {e}")
                                if attempt < 2:
                                    time.sleep(min(2 ** attempt, 60))
                                else:
                                    logging.error(f"Failed to index to Elasticsearch after 3 attempts: {e}")
                    
                    logging.info(f"Processed {len(docs)} certificates from {desc} in batch [{start}, {end}]")
                    start = end + 1
                    end = min(current_size - 1, start + BATCH_SIZE - 1)
                    next_index = start
                
                time.sleep(FETCH_INTERVAL)
        except Exception as e:
            logging.exception(f"{desc}: Exception in monitor loop: {e}")
            time.sleep(FETCH_INTERVAL)

if __name__ == "__main__":
    seen_certs = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
    auth = (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD) if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD else None

    def sig_handler(signum, frame):
        logging.info(f"Received signal ({signum}), shutting down...")
        stop_event.set()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    logs = load_log_list(CT_LOG_LIST_URL)
    if not logs:
        logging.error("No CT logs to monitor. Exiting.")
        exit(1)

    threads = []
    for log in logs:
        name = log.get("description", "CTLog")[:32]
        t = threading.Thread(target=monitor_log, name=name, args=(log, ELASTICSEARCH_HOSTS, ES_INDEX, auth))
        t.daemon = False
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    logging.info("All threads exited. Peace out!")