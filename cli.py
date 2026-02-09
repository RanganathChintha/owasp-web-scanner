import argparse
from scanner.crawler import Crawler
from exploits.sqli_exploit import SQLiExploit
from exploits.xss_exploit import XSSExploit
from exploits.jwt_attack import JWTAttack

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--exploit-sqli", nargs=2, metavar=("URL", "PARAM"))
    parser.add_argument("--exploit-xss", nargs=2, metavar=("URL", "PARAM"))
    parser.add_argument("--exploit-jwt", help="JWT token")
    args = parser.parse_args()

    crawler = Crawler(args.url)
    crawler.crawl()

    if args.exploit_sqli:
        sqli = SQLiExploit(crawler.session)
        result = sqli.exploit(args.exploit_sqli[0], args.exploit_sqli[1])
        print("[EXPLOIT][SQLi]", result)

    if args.exploit_xss:
        xss = XSSExploit(crawler.session)
        result = xss.exploit(args.exploit_xss[0], args.exploit_xss[1])
        print("[EXPLOIT][XSS]", result)

    if args.exploit_jwt:
        jwtatk = JWTAttack()
        print("[EXPLOIT][JWT][alg=none]")
        print(jwtatk.privilege_escalation(args.exploit_jwt))

if __name__ == "__main__":
    main()
