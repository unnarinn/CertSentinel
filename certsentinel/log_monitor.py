import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

from cachetools import TTLCache
from dotenv import load_dotenv

from .ctl_entry import CTLEntry
from .request_handler import RequestHandler

load_dotenv()
ELASTICSEARCH_HOSTS = os.getenv("ELASTICSEARCH_HOSTS", "http://localhost:9200")
ES_INDEX = "CertMonitor"
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
AUTH = (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD) if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD else None


class LogMonitor:
    def __init__(
        self,
        log_info: dict,
        request_handler: RequestHandler,
        stop_event: threading.Event,
        seen_certs: TTLCache,
        seen_lock: threading.Lock,
        file_lock: threading.Lock,
        batch_size: int = 256,
        fetch_interval: int = 60,
    ):
        self.log_info = log_info
        self.request_handler = request_handler
        self.stop_event = stop_event
        self.seen_certs = seen_certs
        self.seen_lock = seen_lock
        self.file_lock = file_lock
        self.batch_size = batch_size
        self.fetch_interval = fetch_interval
        self.desc = log_info.get("description", "CT Log")
        self.url = log_info.get("url", "")
        if not self.url.endswith("/"):
            self.url += "/"
        self.sth_url = self.url + "ct/v1/get-sth"
        self.entries_url = self.url + "ct/v1/get-entries"
        self.next_index = 0
        self.es_bulk_url = f"{ELASTICSEARCH_HOSTS}/_bulk"

    def _initialize_index(self) -> bool:
        """Fetches initial STH and sets the starting index. Returns True on success."""
        logging.info(f"Initializing {self.desc}...")
        sth_data = self.request_handler.get_json(self.sth_url)
        if sth_data and isinstance(sth_data, dict):
            try:
                tree_size = int(sth_data.get("tree_size", 0))
                self.next_index = tree_size
                logging.info(f"Monitoring {self.desc}: starting at index {self.next_index}")
                return True
            except (ValueError, TypeError) as e:
                logging.error(f"Failed to parse initial tree_size for {self.desc}: {e}")
                return False
        else:
            logging.error(f"Failed to fetch or parse initial STH for {self.desc}")
            return False

    def _get_current_tree_size(self) -> Optional[int]:
        """Fetches the current STH and returns the tree size."""
        sth_data = self.request_handler.get_json(self.sth_url)
        if sth_data and isinstance(sth_data, dict):
            try:
                return int(sth_data.get("tree_size", 0))
            except (ValueError, TypeError):
                logging.warning(f"Failed to parse current tree_size for {self.desc}")
                return None
        return None

    def _fetch_entries_batch(self, start: int, end: int) -> Optional[List[Dict[str, Any]]]:
        """Fetches a batch of entries."""
        batch_url = f"{self.entries_url}?start={start}&end={end}"
        entries_data = self.request_handler.get_json(batch_url)
        if entries_data and isinstance(entries_data, dict):
            entries = entries_data.get("entries")
            if isinstance(entries, list):
                return entries
            else:
                logging.warning(f"Entries data from {batch_url} did not contain a list under 'entries'.")
        return None

    def _process_and_filter_entries(self, entries: List[Dict[str, Any]], start_index: int) -> List[CTLEntry]:
        """Processes raw entries, creates CTLEntry objects, filters seen, returns docs."""
        new_entries = []
        for i, entry_data in enumerate(entries):
            current_entry_index = start_index + i
            try:
                ctl_entry = CTLEntry(entry_data, self.url, self.desc, current_entry_index)
                fingerprint = ctl_entry.fingerprint
                should_process = False
                if fingerprint:
                    with self.seen_lock:
                        if fingerprint not in self.seen_certs:
                            self.seen_certs[fingerprint] = True
                            should_process = True

                if should_process and ctl_entry.is_valid:
                    new_entries.append(ctl_entry)
            except Exception as e:
                logging.error(f"Failed to process entry {current_entry_index} for {self.desc}: {e}", exc_info=True)
                continue

        return new_entries

    def _index_batch_to_es(self, docs: List[CTLEntry]) -> bool:
        """Indexes a batch of documents to Elasticsearch"""
        if not docs:
            return True

        bulk_lines = ""
        for doc in docs:
            meta = {"index": {"_index": ES_INDEX}}
            bulk_lines += json.dumps(meta) + "\n"
            bulk_lines += json.dumps(doc.to_dict()) + "\n"

        result = self.request_handler.post_bulk_ndjson(
            url=self.es_bulk_url,
            ndjson_data=bulk_lines,
            auth=AUTH,
            timeout=self.request_handler.default_timeout,
        )

        if result is None:
            logging.error(f"Failed to index batch to Elasticsearch for {self.desc} after retries.")
            return False
        elif isinstance(result, dict) and result.get("errors"):
            logging.error(f"{self.desc}: Bulk index errors reported by Elasticsearch.")
            return True
        else:
            return True

    def _handle_sth_fetch_failure(self):
        """Logs STH fetch failure and waits."""
        logging.warning(f"Could not get current tree size for {self.desc}, retrying after interval.")
        self._wait_for_next_check()

    def _handle_tree_size_decrease(self, current_size: int):
        """Logs tree size decrease and resets the index."""
        logging.warning(f"{self.desc}: Tree size decreased ({current_size} < {self.next_index}). Resetting index.")
        self.next_index = current_size

    def _process_new_entries(self, current_size: int):
        """Fetches, processes, and indexes entries in batches from next_index up to current_size."""
        logging.info(f"{self.desc}: Processing entries from {self.next_index} to {current_size - 1}")
        start = self.next_index
        while start < current_size and not self.stop_event.is_set():
            end = min(current_size - 1, start + self.batch_size - 1)
            logging.debug(f"{self.desc}: Requesting batch [{start}, {end}]")

            raw_entries = self._fetch_entries_batch(start, end)

            if raw_entries is None:
                logging.warning(
                    f"Failed to fetch batch [{start}, {end}] for {self.desc}. Stopping batch processing for this cycle."
                )
                break

            if not raw_entries:
                logging.debug(f"{self.desc}: Received empty batch for [{start}, {end}]")
                start = end + 1
                continue

            new_entries = self._process_and_filter_entries(raw_entries, start)

            if not new_entries:
                continue

            # save new domains to file
            # TODO: make this configurable
            with self.file_lock:
                try:
                    with open("new_domains.txt", "a") as f:
                        for entry in new_entries:
                            if entry.subject_cn:
                                f.write(f"{entry.subject_cn}\n")
                except IOError as e:
                    logging.error(f"Error writing to new_domains.txt: {e}")

            # TODO: also make this configurable
            # Uncomment this to enable Elasticsearch indexing
            # logging.info(f"{self.desc}: Indexing {len(new_entries)} new certificates from batch [{start}, {end}]")
            # if not self._index_batch_to_es(new_entries):
            #     logging.error(
            #         f"Failed to index batch [{start}, {end}] for {self.desc} to Elasticsearch. Stopping batch processing for this cycle."
            #     )
            #     break

            start = end + 1
        self.next_index = start

    def _wait_for_next_check(self):
        """Waits for the fetch interval or until the stop event is set."""
        self.stop_event.wait(self.fetch_interval)

    def run(self):
        """Main monitoring loop for this log."""
        if not self._initialize_index():
            logging.error(f"Initialization failed for {self.desc}. Thread exiting.")
            return

        while not self.stop_event.is_set():
            try:
                current_size = self._get_current_tree_size()
                if current_size is None:
                    self._handle_sth_fetch_failure()
                    continue

                if current_size < self.next_index:
                    self._handle_tree_size_decrease(current_size)

                if current_size > self.next_index:
                    self._process_new_entries(current_size)
                else:
                    logging.debug(f"{self.desc}: No new entries found (Tree size: {current_size}).")

                self._wait_for_next_check()

            except Exception as e:
                # Catch-all for unexpected errors in the loop
                logging.exception(f"{self.desc}: Unhandled exception in monitor loop: {e}")
                # Wait after an exception before retrying
                self._wait_for_next_check()

        logging.info(f"Monitor thread for {self.desc} received stop signal and is exiting.")
