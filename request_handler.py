import requests
import time
import logging
from typing import Optional, Any

class RequestHandler:
    """Handles making HTTP requests with retries and error handling."""
    def __init__(self, session: requests.Session, default_timeout: int = 10, default_max_retries: int = 3):
        self.session = session
        self.default_timeout = default_timeout
        self.default_max_retries = default_max_retries

    def get(self, url: str, timeout: Optional[int] = None, max_retries: Optional[int] = None) -> Optional[requests.Response]:
        """Performs a GET request with configured retry logic."""
        current_timeout = timeout if timeout is not None else self.default_timeout
        current_max_retries = max_retries if max_retries is not None else self.default_max_retries

        for attempt in range(current_max_retries):
            try:
                resp = self.session.get(url, timeout=current_timeout)

                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait_time = int(retry_after) if retry_after and retry_after.isdigit() else min(2 ** attempt, 60)
                    logging.warning(f"429 Too Many Requests for {url}. Waiting {wait_time} seconds (Attempt {attempt + 1}/{current_max_retries})...")
                    time.sleep(wait_time)
                    continue

                resp.raise_for_status()
                return resp

            except requests.exceptions.RequestException as e:
                logging.warning(f"Request to {url} failed: {e}. Attempt {attempt + 1}/{current_max_retries}")
                if attempt < current_max_retries - 1:
                    backoff_time = min(2 ** attempt, 60)
                    time.sleep(backoff_time)
                else:
                    logging.error(f"Request to {url} failed after {current_max_retries} attempts: {e}")
                    return None 
        return None 
    
    def get_json(self, url: str, timeout: Optional[int] = None, max_retries: Optional[int] = None) -> Optional[Any]:
        """Performs a GET request and decodes the response body as JSON."""
        response = self.get(url, timeout=timeout, max_retries=max_retries)
        if response is None:
            return None
        try:
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON response from {url}: {e}")
            return None

