import requests

SENSITIVE_PATHS = [
    "/admin",
    "/dashboard",
    "/admin/dashboard",
    "/manage",
    "/config"
]

class AccessControlScanner:
    def __init__(self, session: requests.Session, base_url):
        self.session = session
        self.base_url = base_url

    def scan_forced_browsing(self):
        findings = []

        for path in SENSITIVE_PATHS:
            url = self.base_url.rstrip("/") + path
            r = self.session.get(url)

            if r.status_code == 200 and "login" not in r.text.lower():
                findings.append({
                    "type": "Broken Access Control",
                    "url": url,
                    "issue": "Forced browsing"
                })

        return findings
