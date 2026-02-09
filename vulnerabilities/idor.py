import requests

class IDORScanner:
    def __init__(self, session: requests.Session):
        self.session = session

    def scan(self, url, params):
        findings = []

        for k, v in params.items():
            if v.isdigit():
                original = self.session.get(url, params=params)
                test_params = params.copy()
                test_params[k] = str(int(v) + 1)

                test = self.session.get(url, params=test_params)

                if test.status_code == 200 and test.text != original.text:
                    findings.append({
                        "type": "IDOR",
                        "param": k,
                        "original": v,
                        "tested": test_params[k],
                        "url": url
                    })

        return findings
