import argparse
from urllib.parse import urlparse, parse_qs
from scanner.crawler import Crawler
from vulnerabilities.sqli import SQLiScanner
from vulnerabilities.xss import XSSScanner
from vulnerabilities.idor import IDORScanner
from vulnerabilities.access_control import AccessControlScanner

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--sqli", action="store_true")
    parser.add_argument("--xss", action="store_true")
    parser.add_argument("--idor", action="store_true")
    parser.add_argument("--access", action="store_true")
    args = parser.parse_args()

    crawler = Crawler(args.url)
    crawler.crawl()
    endpoints = crawler.get_endpoints()

    print("\n[+] Discovered Endpoints:")
    for ep in endpoints:
        print(ep)

    parsed_root = urlparse(args.url)
    base_root = parsed_root.scheme + "://" + parsed_root.netloc

    if args.idor:
        print("\n[+] Running IDOR Scan")
        idor = IDORScanner(crawler.session)

        for ep in endpoints:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            if not params:
                continue

            flat = {k: v[0] for k, v in params.items()}
            base = parsed.scheme + "://" + parsed.netloc + parsed.path

            results = idor.scan(base, flat)
            for r in results:
                print(f"[VULNERABLE][IDOR] {ep}")
                print(r)

    if args.access:
        print("\n[+] Running Access Control Scan")
        ac = AccessControlScanner(crawler.session, base_root)
        results = ac.scan_forced_browsing()

        for r in results:
            print(f"[VULNERABLE][ACCESS] {r['url']}")
            print(r)

if __name__ == "__main__":
    main()