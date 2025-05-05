#!/usr/bin/env python3
import logging
import signal
import threading

import requests
from cachetools import TTLCache

from ct_log_list_provider import CTLogListProvider
from log_monitor import LogMonitor
from request_handler import RequestHandler

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

if __name__ == "__main__":
    seen_lock = threading.Lock()
    stop_event = threading.Event()
    session = requests.Session()
    request_handler = RequestHandler(session, REQUEST_TIMEOUT)
    seen_certs = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)

    def sig_handler(signum, frame):
        logging.info(f"Received signal ({signum}), shutting down...")
        stop_event.set()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    log_provider = CTLogListProvider(CT_LOG_LIST_URL, request_handler)
    logs_to_monitor = log_provider.get_logs()

    if not logs_to_monitor:
        logging.error("No usable CT logs found to monitor. Exiting.")
        exit(1)

    threads = []
    logging.info(f"Starting monitors for {len(logs_to_monitor)} logs...")
    for log_info in logs_to_monitor:
        monitor_instance = LogMonitor(
            log_info=log_info,
            request_handler=request_handler,
            stop_event=stop_event,
            seen_certs=seen_certs,
            seen_lock=seen_lock,
            batch_size=BATCH_SIZE,
            fetch_interval=FETCH_INTERVAL,
        )

        thread_name = monitor_instance.desc[:32]
        t = threading.Thread(target=monitor_instance.run, name=thread_name)
        t.daemon = False
        t.start()
        threads.append(t)

    logging.info("All monitor threads started. Waiting for completion or signal...")
    for t in threads:
        t.join()

    logging.info("All monitor threads have exited. Peace out!")
