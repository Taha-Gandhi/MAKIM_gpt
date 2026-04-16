import json
import os
from datetime import datetime


class ReportAgent:

    def calculate_severity(self, anomaly_findings, pattern_findings):
        score = 0

        score += len(anomaly_findings.get("new_modules", [])) * 2
        score += len(anomaly_findings.get("missing_modules", [])) * 2

        if anomaly_findings.get("pid_alert", False):
            score += 2

        score += pattern_findings.get("risk_score", 0)

        if score >= 8:
            return "HIGH"
        elif score >= 4:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_report(self, snapshot, anomaly_findings, pattern_findings):
        severity = self.calculate_severity(anomaly_findings, pattern_findings)

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "summary": {
                "module_count": len(snapshot.get("modules", [])),
                "pid_count": len(snapshot.get("pids", []))
            },
            "anomalies": anomaly_findings,
            "patterns": pattern_findings
        }

        return report

    def save_report(self, report):
        os.makedirs("reports", exist_ok=True)

        filename = f"reports/report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return filename

    def print_report(self, report):
        print("\n========== MAKIM REPORT ==========")
        print(f"Severity: {report['severity']}")
        print(f"Modules: {report['summary']['module_count']}")
        print(f"PIDs: {report['summary']['pid_count']}")

        print("\n--- Anomalies ---")
        for key, value in report["anomalies"].items():
            print(f"{key}: {value}")

        print("\n--- Pattern Analysis ---")
        for key, value in report["patterns"].items():
            print(f"{key}: {value}")

        print("==================================\n")