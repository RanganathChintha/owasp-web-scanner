import base64
import json
import jwt
import requests
from jwt import InvalidTokenError

COMMON_SECRETS = [
    "secret", "password", "admin", "jwtsecret", "123456", "qwerty"
]

class JWTAnalyzer:
    def __init__(self, session: requests.Session):
        self.session = session

    def _b64decode(self, segment):
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    def decode_without_verify(self, token):
        header_b64, payload_b64, _ = token.split(".")
        header = json.loads(self._b64decode(header_b64))
        payload = json.loads(self._b64decode(payload_b64))
        return header, payload

    def check_alg_none(self, token):
        header, _ = self.decode_without_verify(token)
        if header.get("alg", "").lower() == "none":
            return {
                "type": "JWT alg=none",
                "issue": "Unsigned token accepted"
            }
        return None

    def brute_force_secret(self, token):
        for secret in COMMON_SECRETS:
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return {
                    "type": "Weak JWT secret",
                    "secret": secret
                }
            except InvalidTokenError:
                continue
        return None

    def tamper_payload(self, token):
        header, payload = self.decode_without_verify(token)
        if "role" in payload:
            payload["role"] = "admin"
            return {
                "type": "JWT tampering possible",
                "modified_claim": "role=admin"
            }
        return None

    def analyze(self, token):
        findings = []

        f1 = self.check_alg_none(token)
        if f1:
            findings.append(f1)

        f2 = self.brute_force_secret(token)
        if f2:
            findings.append(f2)

        f3 = self.tamper_payload(token)
        if f3:
            findings.append(f3)

        return findings
