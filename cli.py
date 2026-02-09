import argparse
from scanner.crawler import Crawler

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    args = parser.parse_args()

    crawler = Crawler(args.url)
    crawler.crawl()

    print("\n[+] Discovered Endpoints:")
    for ep in crawler.get_endpoints():
        print(ep)

if __name__ == "__main__":
    main()
