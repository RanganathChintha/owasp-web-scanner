import argparse
from urllib.parse import urlparse, parse_qs
from scanner.crawler import Crawler
from vulnerabilities.idor import IDORScanner
from vulnerabilities.access_control import AccessControlScanner
from vulnerabilities.jwt import JWTAnalyzer

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--idor", action="store_true")
    parser.add_argument("--access", action="store_true")
    parser.add_argument("--jwt", help="JWT token to analyze")
    args = parser.parse_args()

    crawler = Crawler(args.url)
    crawler.crawl()
    endpoints = crawler.get_endpoints()

    parsed_root = urlparse(args.url)
    base_root = parsed_root.scheme + "://" + parsed_root.netloc

    if args.idor:
        idor = IDORScanner(crawler.session)
        for ep in endpoints:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            if not params:
                continue
            flat = {k: v[0] for k, v in params.items()}
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            for r in idor.scan(base, flat):
                print("[VULNERABLE][IDOR]", r)

    if args.access:
        ac = AccessControlScanner(crawler.session, base_root)
        for r in ac.scan_forced_browsing():
            print("[VULNERABLE][ACCESS]", r)

    if args.jwt:
        print("\n[+] Running JWT Analysis")
        analyzer = JWTAnalyzer(crawler.session)
        findings = analyzer.analyze(args.jwt)
        for f in findings:
            print("[VULNERABLE][JWT]", f)

if __name__ == "__main__":
    main()
