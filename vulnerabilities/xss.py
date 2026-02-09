import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

class XSSScanner:
    def __init__(self, session: requests.Session):
        self.session = session

    def scan_reflected(self, url, params, log):
        log(f"[XSS] scan_reflected() entered for {url}")

        if not params:
            log("[XSS] No parameters → skipping")
            return

        payload = "<script>alert(1)</script>"

        for k in params:
            log(f"[XSS] Injecting param {k}")
            test = params.copy()
            test[k] = payload

            r = self.session.get(url, params=test)
            if payload in r.text:
                log(f"[XSS][VULNERABLE] param={k}")
                return

        log("[XSS] scan_reflected() finished → NOT vulnerable")
 

    def scan_basic_stored(self, submit_url, params):
        injected = False

        for k in params:
            params[k] = XSS_PAYLOADS[0]

        self.session.post(submit_url, data=params)
        r = self.session.get(submit_url)

        if XSS_PAYLOADS[0] in r.text:
            injected = True

        if injected:
            return {
                "type": "Stored XSS (Basic)",
                "payload": XSS_PAYLOADS[0],
                "url": submit_url
            }

        return None
