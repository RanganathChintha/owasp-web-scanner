import argparse
from urllib.parse import urlparse, parse_qs
from scanner.crawler import Crawler
from vulnerabilities.sqli import SQLiScanner
from vulnerabilities.xss import XSSScanner

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--sqli", action="store_true", help="Run SQLi scan")
    parser.add_argument("--xss", action="store_true", help="Run XSS scan")
    args = parser.parse_args()

    crawler = Crawler(args.url)
    crawler.crawl()
    endpoints = crawler.get_endpoints()

    print("\n[+] Discovered Endpoints:")
    for ep in endpoints:
        print(ep)

    if args.sqli:
        print("\n[+] Running SQL Injection Scan")
        sqli = SQLiScanner(crawler.session)

        for ep in endpoints:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            if not params:
                continue

            flat = {k: v[0] for k, v in params.items()}
            base = parsed.scheme + "://" + parsed.netloc + parsed.path

            for fn in (
                sqli.scan_error_based,
                sqli.scan_boolean_based,
                sqli.scan_time_based,
            ):
                res = fn(base, flat)
                if res:
                    print(f"[VULNERABLE][SQLi] {ep}")
                    print(res)

    if args.xss:
        print("\n[+] Running XSS Scan")
        xss = XSSScanner(crawler.session)

        for ep in endpoints:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            if not params:
                continue

            flat = {k: v[0] for k, v in params.items()}
            base = parsed.scheme + "://" + parsed.netloc + parsed.path

            findings = xss.scan_reflected(base, flat)
            for f in findings:
                print(f"[VULNERABLE][XSS] {ep}")
                print(f)

if __name__ == "__main__":
    main()
