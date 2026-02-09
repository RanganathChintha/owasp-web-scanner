import argparse
from reports.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="OWASP Web Vulnerability Scanner")
    parser.add_argument("--report", action="store_true", help="Generate demo report")
    args = parser.parse_args()

    if args.report:
        report = ReportGenerator()
        report.add_finding(
            "SQL Injection",
            "/products?id=1",
            "1' OR '1'='1",
            "Database compromise",
            9.1,
            "Use parameterized queries"
        )
        report.add_finding(
            "Reflected XSS",
            "/search?q=test",
            "<script>alert(1)</script>",
            "Session hijacking",
            6.5,
            "Escape output and use CSP"
        )

        file = report.generate_html()
        print("[+] Report generated:", file)

if __name__ == "__main__":
    main()
