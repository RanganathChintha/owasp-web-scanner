import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from urllib.parse import urlparse, parse_qs

from scanner.crawler import Crawler
from vulnerabilities.sqli import SQLiScanner
from vulnerabilities.xss import XSSScanner
from vulnerabilities.idor import IDORScanner
from vulnerabilities.access_control import AccessControlScanner
from vulnerabilities.jwt import JWTAnalyzer


def run_full_scan_stream(target_url, jwt_token=None):

    def log(msg):
        # central logging point
        yield msg

    yield "[SCAN] Starting scan"

    crawler = Crawler(target_url)
    crawler.crawl()
    endpoints = crawler.get_endpoints()

    yield f"[CRAWLER] Found {len(endpoints)} endpoints"

    session = crawler.session

    # ---------- SQLi ----------
    yield "[SQLi] Starting"
    sqli = SQLiScanner(session)

    for ep in endpoints:
        parsed = urlparse(ep)
        params = parse_qs(parsed.query)

        flat = {k: v[0] for k, v in params.items()}
        base = parsed.scheme + "://" + parsed.netloc + parsed.path

        yield f"[SQLi] Calling scan_error_based() on {ep}"
        sqli.scan_error_based(base, flat, log)

    # ---------- XSS ----------
    yield "[XSS] Starting"
    xss = XSSScanner(session)

    for ep in endpoints:
        parsed = urlparse(ep)
        params = parse_qs(parsed.query)

        flat = {k: v[0] for k, v in params.items()}
        base = parsed.scheme + "://" + parsed.netloc + parsed.path

        yield f"[XSS] Calling scan_reflected() on {ep}"
        xss.scan_reflected(base, flat, log)

    # ---------- IDOR ----------
    yield "[IDOR] Starting"
    idor = IDORScanner(session)

    for ep in endpoints:
        parsed = urlparse(ep)
        params = parse_qs(parsed.query)

        flat = {k: v[0] for k, v in params.items()}
        base = parsed.scheme + "://" + parsed.netloc + parsed.path

        yield f"[IDOR] Calling scan() on {ep}"
        idor.scan(base, flat, log)

    # ---------- ACCESS CONTROL ----------
    yield "[ACCESS] Starting"
    parsed_root = urlparse(target_url)
    base_root = parsed_root.scheme + "://" + parsed_root.netloc

    ac = AccessControlScanner(session, base_root)
    ac.scan_forced_browsing(log)

    # ---------- JWT ----------
    if jwt_token:
        yield "[JWT] Starting"
        jwt_results = JWTAnalyzer(session).analyze(jwt_token)
        for r in jwt_results:
            yield f"[JWT][ISSUE] {r}"

    yield "[SCAN COMPLETE]"
