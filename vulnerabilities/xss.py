import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]

class XSSScanner:
    def __init__(self, session: requests.Session):
        self.session = session

    def scan_reflected(self, url, params):
        findings = []

        for k in params:
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[k] = payload

                r = self.session.get(url, params=test_params)

                if payload in r.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "param": k,
                        "payload": payload,
                        "url": url
                    })

        return findings

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
