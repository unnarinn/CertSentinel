import base64
import logging
from construct import Container
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timezone
import time
import hashlib
from typing import Optional, List, Dict, Any
import ctl_structs 

class CTLEntry:
    """
    A class representing an entry in a certificate transparency log.
    """
    def __init__(self, raw_entry: dict, log_url: str, log_name: str, index: int):
        self._raw_entry = raw_entry
        self.log_url = log_url
        self.cert_index = index
        self.log_name = log_name
        self.leaf_cert_bytes: Optional[bytes] = None
        self.extra_data_bytes: Optional[bytes] = None
        self.leaf_header: Optional[Container] = None
        self.cert: Optional[x509.Certificate] = None
        self.chain: Optional[List[x509.Certificate]] = None
        self.fingerprint: Optional[str] = None
        self.timestamp_ms: int = int(time.time() * 1000)
        self.type: str = "x509"
        self.update_type: Optional[str] = None
        self.version: Optional[int] = None
        self.serial_number: Optional[str] = None
        self.signature_algorithm: Optional[str] = None
        self.issuer_cn: Optional[str] = None
        self.subject_cn: Optional[str] = None
        self.validity: Dict[str, Any] = {}
        self.subject_public_key_info: Dict[str, Any] = {}
        self.all_domains: List[str] = []
        self.ocsp_url: Optional[str] = None
        self.issuer_cert_url: Optional[str] = None
        self.crl_url: Optional[str] = None
        self.key_usage: List[str] = []
        self.extended_key_usage: List[str] = []
        self.cert_link: Optional[str] = None
        self.at_timestamp: Optional[str] = None
        self.seen: Optional[str] = None
        self.source: Dict[str, Any] = {}
        self.chain_summary: List[Dict[str, Any]] = []
        self.is_valid = False

        self._initialize_entry()

    def _initialize_entry(self):
        """Parses the raw entry data and populates the instance attributes."""
        leaf_b64 = self._raw_entry.get("leaf_input")
        extra_b64 = self._raw_entry.get("extra_data")
        if not leaf_b64 or not extra_b64:
            logging.warning("Missing leaf_input or extra_data")
            return

        try:
            self.leaf_cert_bytes = base64.b64decode(leaf_b64)
            self.extra_data_bytes = base64.b64decode(extra_b64)
        except Exception as e:
            logging.warning(f"Base64 decoding error: {e}")
            return

        if len(self.leaf_cert_bytes) < 12:
             logging.warning("Leaf input too short")
             return

        try:
            self.leaf_header = ctl_structs.MerkleTreeHeader.parse(self.leaf_cert_bytes)
            cert_data: Optional[bytes] = None
            if self.leaf_header.LogEntryType == "X509LogEntryType":
                self.update_type = "X509LogEntry"
                cert_data = ctl_structs.Certificate.parse(self.leaf_header.Entry).CertData
                self.cert = x509.load_der_x509_certificate(cert_data, default_backend())
                extra_parsed = ctl_structs.CertificateChain.parse(self.extra_data_bytes)
                self.chain = [x509.load_der_x509_certificate(c.CertData, default_backend()) for c in extra_parsed.Chain]
            elif self.leaf_header.LogEntryType == "PrecertLogEntryType":
                self.update_type = "PrecertLogEntry"
                extra_parsed = ctl_structs.PreCertEntry.parse(self.extra_data_bytes)
                cert_data = extra_parsed.LeafCert.CertData
                self.cert = x509.load_der_x509_certificate(cert_data, default_backend())
                self.chain = [x509.load_der_x509_certificate(c.CertData, default_backend()) for c in extra_parsed.ChainData.Chain]
            else:
                 logging.warning(f"Unknown LogEntryType: {self.leaf_header.LogEntryType}")
                 return

            if not self.cert or cert_data is None:
                 logging.warning("Certificate could not be loaded")
                 return

            self.fingerprint = hashlib.sha256(cert_data).hexdigest().upper()
            self.version = self.cert.version.value + 1 # x509.Version is 0-indexed (v1=0, v2=1, v3=2)
            self.serial_number = str(self.cert.serial_number)
            pk_algorithm, pk_key_size, pk_public_exponent, pk_curve_name = self._get_public_key_info(self.cert)
            self.subject_public_key_info = {
                "algorithm": pk_algorithm,
                "key_size_bits": pk_key_size,
                "public_exponent": pk_public_exponent,
                "curve_name": pk_curve_name
            }
            self.signature_algorithm = f"{self.cert.signature_hash_algorithm.name}_{pk_algorithm}" if self.cert.signature_hash_algorithm else pk_algorithm
            self.issuer_cn = self._get_issuer_name(self.cert)
            subject_cn_attr = self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            self.subject_cn = subject_cn_attr[0].value if subject_cn_attr else None
            not_before_utc = self.cert.not_valid_before_utc
            not_after_utc = self.cert.not_valid_after_utc
            self.validity = {
                "not_before": not_before_utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "not_after": not_after_utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "valid_days": self._calculate_valid_days(not_before_utc, not_after_utc)
            }
            self.all_domains = self._get_domains_from_cert(self.cert)
            self.ocsp_url, self.issuer_cert_url = self._get_aia_info(self.cert)
            self.crl_url = self._get_crl_url(self.cert)
            self.key_usage = self._get_key_usage(self.cert)
            self.extended_key_usage = self._get_extended_key_usage(self.cert)
            self.cert_link = f"{self.log_url}ct/v1/get-entries?start={self.cert_index}&end={self.cert_index}"
            current_time_iso = datetime.now(timezone.utc).isoformat(timespec='milliseconds') + "Z"
            self.at_timestamp = current_time_iso
            self.seen = current_time_iso
            self.source = {
                "url": self.log_url,
                "name": self.log_name
            }
            self.chain_summary = self._get_chain_summary(self.chain)

            self.is_valid = True # successfully initialized

        except Exception as e:
            logging.error(f"Error initializing CTLEntry at index {self.cert_index} for {self.log_url}: {e}", exc_info=True)
            self.is_valid = False

    def to_dict(self) -> Optional[Dict[str, Any]]:
        if not self.is_valid:
            return None

        return {
            "log_url": self.log_url,
            "timestamp": self.timestamp_ms,
            "type": self.type,
            "update_type": self.update_type,
            "fingerprint": self.fingerprint,
            "version": self.version,
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
            "issuer_cn": self.issuer_cn,
            "subject_cn": self.subject_cn,
            "validity": self.validity,
            "subject_public_key_info": self.subject_public_key_info,
            "all_domains": self.all_domains,
            "ocsp_url": self.ocsp_url,
            "issuer_cert_url": self.issuer_cert_url,
            "crl_url": self.crl_url,
            "key_usage": self.key_usage,
            "extended_key_usage": self.extended_key_usage,
            "cert_index": self.cert_index,
            "cert_link": self.cert_link,
            "@timestamp": self.at_timestamp,
            "seen": self.seen,
            "source": self.source,
            "chain_summary": self.chain_summary
        }

    def _get_domains_from_cert(self, cert: x509.Certificate) -> list:
        """Extracts all domain names from the certificate."""
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


    def _calculate_valid_days(self, not_before: datetime, not_after: datetime) -> int:
        """Calculates the number of valid days between not_before and not_after."""
        return (not_after - not_before).days
    
    def _get_key_usage(self, cert: x509.Certificate) -> list:
        """Extracts key usage from the certificate."""
        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            usage = []
            if getattr(ku, 'digital_signature', False): usage.append("digital_signature")
            if getattr(ku, 'content_commitment', False): usage.append("content_commitment")
            if getattr(ku, 'key_encipherment', False): usage.append("key_encipherment")
            if getattr(ku, 'data_encipherment', False): usage.append("data_encipherment")
            if getattr(ku, 'key_agreement', False): usage.append("key_agreement")
            if getattr(ku, 'key_cert_sign', False): usage.append("key_cert_sign")
            if getattr(ku, 'crl_sign', False): usage.append("crl_sign")
            return usage
        except x509.ExtensionNotFound:
            return []
        except Exception as e:
             logging.warning(f"Error processing KeyUsage for {self.fingerprint}: {e}")
             return []


    def _get_extended_key_usage(self, cert: x509.Certificate) -> list:
        """Extracts extended key usage from the certificate."""
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            return [usage._name.lower() for usage in eku]
        except x509.ExtensionNotFound:
            return []

    def _get_issuer_name(self, cert: x509.Certificate) -> str:
        """Extracts the issuer name from the certificate."""
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

    def _get_public_key_info(self, cert: x509.Certificate) -> tuple:
        """Extracts algorithm, key size, and other relevant info from the public key."""
        public_key = cert.public_key()
        algorithm = "unknown"
        key_size = None
        public_exponent = None
        curve_name = None

        if isinstance(public_key, rsa.RSAPublicKey):
            algorithm = "rsa"
            key_size = public_key.key_size
            try:
                public_exponent = public_key.public_numbers().e
            except Exception: 
                public_exponent = None
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algorithm = "ec"
            key_size = public_key.key_size
            try:
                curve_name = public_key.curve.name
            except Exception: 
                curve_name = None

        return algorithm, key_size, public_exponent, curve_name

    def _get_aia_info(self, cert: x509.Certificate) -> tuple:
        """Extracts OCSP and Issuer URLs from Authority Information Access."""
        ocsp_url = None
        issuer_url = None
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ocsp_urls = [ad.access_location.value for ad in aia if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
            issuer_urls = [ad.access_location.value for ad in aia if ad.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS]
            ocsp_url = ocsp_urls[0] if ocsp_urls else None
            issuer_url = issuer_urls[0] if issuer_urls else None
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logging.warning(f"Error processing AIA for {self.fingerprint}: {e}")
            pass
        return ocsp_url, issuer_url

    def _get_crl_url(self, cert: x509.Certificate) -> Optional[str]:
        """Extracts the first CRL Distribution Point URL."""
        try:
            crl_dps = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            crl_urls = [dp.full_name[0].value for dp in crl_dps if dp.full_name]
            crl_url = crl_urls[0] if crl_urls else None
        except x509.ExtensionNotFound:
            crl_url = None
        return crl_url


    def _get_chain_summary(self, chain: Optional[List[x509.Certificate]]) -> List[Dict[str, Any]]:
        """Creates a summary of the certificate chain."""
        summary = []
        if not chain:
            return summary
        for chain_cert in chain:
            try:
                cn_attr = chain_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = cn_attr[0].value if cn_attr else self._get_issuer_name(chain_cert) 
                not_after = chain_cert.not_valid_after_utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                summary.append({"cn": cn, "not_after": not_after})
            except Exception as e:
                 logging.warning(f"Error processing chain cert summary: {e}")
                 summary.append({"cn": "Error Processing", "not_after": None}) 
        return summary