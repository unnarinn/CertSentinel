import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .request_handler import RequestHandler


class CTLogListProvider:
    """
    Provides a list of usable CT logs from a specified URL.
    """

    def __init__(self, list_url: str, request_handler: RequestHandler):
        self.list_url = list_url
        self.request_handler = request_handler
        self._usable_logs: Optional[List[Dict[str, Any]]] = None

    def _fetch_raw_list(self) -> Optional[Dict[str, Any]]:
        """Fetches the raw log list JSON data from the CT log list URL."""
        raw_data = self.request_handler.get_json(self.list_url)
        if isinstance(raw_data, dict):
            return raw_data
        elif raw_data is not None:
            logging.warning(f"Expected a dictionary from {self.list_url}, but got type {type(raw_data)}.")
        return None

    def _filter_logs(self, data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filters the raw log data for usable and active logs."""
        if not data:
            return []

        raw_log_entries = []
        if "logs" in data and isinstance(data.get("logs"), list):
            raw_log_entries = data["logs"]
        elif "operators" in data and isinstance(data.get("operators"), list):
            raw_log_entries = [
                log
                for operator in data["operators"]
                if isinstance(operator, dict) and isinstance(operator.get("logs"), list)
                for log in operator["logs"]
            ]
        else:
            logging.warning(f"Unexpected structure in CT log list data from {self.list_url}.")
            return []

        usable_logs = []
        now = datetime.now(timezone.utc)
        for log in raw_log_entries:
            if not isinstance(log, dict):
                continue

            state = log.get("state")
            if not isinstance(state, dict) or "usable" not in state:
                continue

            interval = log.get("temporal_interval")
            if isinstance(interval, dict):
                try:
                    start_str = interval.get("start_inclusive")
                    end_str = interval.get("end_exclusive")
                    if start_str and end_str:
                        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                        if not (start <= now < end):
                            continue
                except (ValueError, TypeError) as e:
                    log_desc = log.get("description", "Unknown Log")
                    logging.warning(f"Cannot parse temporal_interval for log '{log_desc}': {e}. Skipping log.")
                    continue

            usable_logs.append(log)
        return usable_logs

    def get_logs(self, force_reload: bool = False) -> List[Dict[str, Any]]:
        """
        Returns the list of usable logs. Fetches/filters if not already loaded
        or if force_reload is True.
        """
        if self._usable_logs is None or force_reload:
            logging.info(f"Loading/Reloading CT log list from {self.list_url}...")
            raw_data = self._fetch_raw_list()
            self._usable_logs = self._filter_logs(raw_data)
            logging.info(f"Found {len(self._usable_logs)} usable CT logs.")
        return self._usable_logs if self._usable_logs is not None else []
