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

    def scan_forced_browsing(self, log):
        log("[ACCESS] scan_forced_browsing() entered")

        for path in ["/admin", "/dashboard"]:
            url = self.base_url + path
            log(f"[ACCESS] Trying {url}")

            r = self.session.get(url)
            if r.status_code == 200:
                log(f"[ACCESS][VULNERABLE] {url}")
                return

        log("[ACCESS] No forced browsing issues")
