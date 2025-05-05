import logging
import signal
import threading
import sys
import time

import requests
from cachetools import TTLCache

from .ct_log_list_provider import CTLogListProvider
from .log_monitor import LogMonitor
from .request_handler import RequestHandler

# Default configuration values
CT_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
FETCH_INTERVAL = 60
BATCH_SIZE = 256
CACHE_MAXSIZE = 100000
CACHE_TTL = 3600
REQUEST_TIMEOUT = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class CertSentinel:
    """Main application class for monitoring Certificate Transparency logs."""

    def __init__(self):
        """Initialize shared resources and components."""
        self.stop_event = threading.Event()
        self.seen_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.seen_certs = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)
        self.session = requests.Session()
        self.request_handler = RequestHandler(self.session, REQUEST_TIMEOUT)
        self.log_provider = CTLogListProvider(CT_LOG_LIST_URL, self.request_handler)
        self.threads = []

    def _setup_signal_handlers(self):
        """Sets up handlers for SIGINT and SIGTERM."""

        def sig_handler(signum, frame):
            logging.info(f"Received signal ({signum}), initiating shutdown...")
            self.stop_event.set()

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        logging.info("Signal handlers set up.")

    def start_monitors(self):
        """Fetches the log list and starts a monitor thread for each log."""
        logs_to_monitor = self.log_provider.get_logs()

        if not logs_to_monitor:
            logging.error("No usable CT logs found to monitor. Exiting.")
            return False

        logging.info(f"Starting monitors for {len(logs_to_monitor)} logs...")
        for log_info in logs_to_monitor:
            monitor_instance = LogMonitor(
                log_info=log_info,
                request_handler=self.request_handler,
                stop_event=self.stop_event,
                seen_certs=self.seen_certs,
                seen_lock=self.seen_lock,
                file_lock=self.file_lock,
                batch_size=BATCH_SIZE,
                fetch_interval=FETCH_INTERVAL,
            )

            thread_name = monitor_instance.desc[:32]
            t = threading.Thread(target=monitor_instance.run, name=thread_name)
            t.daemon = False
            t.start()
            self.threads.append(t)

        logging.info("All monitor threads started.")
        return True

    def wait_for_completion(self):
        """Waits for all monitor threads to finish."""
        logging.info("Waiting for monitor threads to complete...")
        for t in self.threads:
            try:
                t.join()
            except Exception as e:
                logging.error(f"Exception joining thread {t.name}: {e}")

        logging.info("All monitor threads have exited.")

    def run(self):
        """Sets up signals, starts monitors, and waits for completion."""
        self._setup_signal_handlers()

        if not self.start_monitors():
            sys.exit(1)

        try:
            while not self.stop_event.is_set():
                # Keep main thread alive
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt in main loop, ensuring shutdown...")
            self.stop_event.set()
        finally:
            self.wait_for_completion()

        logging.info("CertSentinel application shutting down.")


if __name__ == "__main__":
    app = CertSentinel()
    app.run()
