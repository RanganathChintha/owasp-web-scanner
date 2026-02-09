class SQLiScanner:
    def __init__(self, session):
        self.session = session

    def scan_error_based(self, url, params, log):
        log(f"[SQLi] scan_error_based() entered for {url}")

        if not params:
            log("[SQLi] No parameters → skipping")
            return

        for k in params:
            log(f"[SQLi] Testing param {k}")
            test = params.copy()
            test[k] += "'"

            r = self.session.get(url, params=test)
            if "sql" in r.text.lower():
                log(f"[SQLi][VULNERABLE] param={k}")
                return

        log("[SQLi] scan_error_based() finished → NOT vulnerable")

