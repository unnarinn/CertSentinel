#!/usr/bin/env python3
import threading
import logging
import signal
from datetime import datetime, timezone
import time
from typing import Optional
import requests
from cachetools import TTLCache
import json
from dotenv import load_dotenv
import os
from ctl_entry import CTLEntry

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

def monitor_log(log_info: dict, ELASTICSEARCH_HOSTS: str, es_index: str, auth: Optional[tuple]):
    desc = log_info.get("description", "CT Log")
    url = log_info.get("url", "")
    if not url.endswith("/"):
        url += "/"
    
    sth_url = url + "ct/v1/get-sth"
    entries_url = url + "ct/v1/get-entries"
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
                    batch_url = f"{entries_url}?start={start}&end={end}"
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
                        try:
                            ctl_entry = CTLEntry(entry, url, desc, idx)
                        except Exception as e:
                            logging.error(f"Failed to create entry {idx} for {desc}: {e}")
                            continue

                        with seen_lock:
                            if ctl_entry.fingerprint in seen_certs:
                                continue
                            seen_certs[ctl_entry.fingerprint] = True

                        if ctl_entry.is_valid:
                            print(ctl_entry.subject_cn)
                            docs.append(ctl_entry.to_dict())

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