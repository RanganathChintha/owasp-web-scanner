from jinja2 import Environment, FileSystemLoader
import datetime

class ReportGenerator:
    def __init__(self):
        self.findings = []

    def add_finding(self, vuln, url, payload, impact, cvss, fix):
        self.findings.append({
            "vulnerability": vuln,
            "url": url,
            "payload": payload,
            "impact": impact,
            "cvss": cvss,
            "severity": self._severity(cvss),
            "fix": fix
        })

    def _severity(self, cvss):
        if cvss >= 9:
            return "critical"
        elif cvss >= 7:
            return "high"
        elif cvss >= 4:
            return "medium"
        return "low"

    def generate_html(self):
        env = Environment(loader=FileSystemLoader("reports/templates"))
        template = env.get_template("report.html")
        html = template.render(findings=self.findings)
        filename = f"reports/scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.html"

        with open(filename, "w") as f:
            f.write(html)

        return filename
