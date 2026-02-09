import argparse
from urllib.parse import urlparse, parse_qs
from scanner.crawler import Crawler
from vulnerabilities.sqli import SQLiScanner

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--sqli", action="store_true", help="Run SQLi scan")
    args = parser.parse_args()

    crawler = Crawler(args.url)
    crawler.crawl()
    endpoints = crawler.get_endpoints()

    print("\n[+] Discovered Endpoints:")
    for ep in endpoints:
        print(ep)

    if args.sqli:
        print("\n[+] Running SQL Injection Scan")
        scanner = SQLiScanner(crawler.session)

        for ep in endpoints:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            if not params:
                continue

            flat_params = {k: v[0] for k, v in params.items()}

            for fn in (
                scanner.scan_error_based,
                scanner.scan_boolean_based,
                scanner.scan_time_based,
            ):
                result = fn(parsed.scheme + "://" + parsed.netloc + parsed.path, flat_params)
                if result:
                    print(f"[VULNERABLE] {ep}")
                    print(result)

if __name__ == "__main__":
    main()
