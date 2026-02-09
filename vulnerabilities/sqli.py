import time
import requests

ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite error",
]

BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
]

TIME_PAYLOAD = "1' AND SLEEP(5)-- "

class SQLiScanner:
    def __init__(self, session: requests.Session):
        self.session = session

    def _has_sql_error(self, text):
        t = text.lower()
        return any(e in t for e in ERROR_PATTERNS)

    def scan_error_based(self, url, params):
        for k in params:
            test = params.copy()
            test[k] = params[k] + "'"
            r = self.session.get(url, params=test)
            if self._has_sql_error(r.text):
                return {
                    "type": "Error-based SQLi",
                    "param": k,
                    "payload": test[k]
                }
        return None

    def scan_boolean_based(self, url, params):
        for k in params:
            true_p, false_p = BOOLEAN_PAYLOADS[0]
            p_true = params.copy()
            p_false = params.copy()
            p_true[k] = true_p
            p_false[k] = false_p

            r1 = self.session.get(url, params=p_true)
            r2 = self.session.get(url, params=p_false)

            if r1.text != r2.text:
                return {
                    "type": "Boolean-based SQLi",
                    "param": k,
                    "payloads": (true_p, false_p)
                }
        return None

    def scan_time_based(self, url, params):
        for k in params:
            p = params.copy()
            p[k] = TIME_PAYLOAD

            start = time.time()
            self.session.get(url, params=p)
            elapsed = time.time() - start

            if elapsed >= 5:
                return {
                    "type": "Time-based SQLi",
                    "param": k,
                    "payload": TIME_PAYLOAD
                }
        return None
