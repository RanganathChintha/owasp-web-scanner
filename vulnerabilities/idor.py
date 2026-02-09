import requests

class IDORScanner:
    def __init__(self, session: requests.Session):
        self.session = session

    def scan(self, url, params, log):
        log(f"[IDOR] scan() entered for {url}")

        if not params:
            log("[IDOR] No parameters → skipping")
            return

        for k, v in params.items():
            if not v.isdigit():
                log(f"[IDOR] {k} not numeric → skipping")
                continue

            log(f"[IDOR] Testing {k}")
            test = params.copy()
            test[k] = str(int(v) + 1)

            r = self.session.get(url, params=test)
            if r.status_code == 200:
                log(f"[IDOR][POTENTIAL] param={k}")
                return

        log("[IDOR] scan() finished → NOT vulnerable")

