class AnomalyDetector:

    def compare(self, baseline, current):
        findings = {
            "new_modules": [],
            "missing_modules": [],
            "new_pids": [],
            "missing_pids": [],
            "pid_change_count": 0,
            "pid_alert": False
        }

        baseline_modules = set(baseline.get("modules", []))
        current_modules = set(current.get("modules", []))

        baseline_pids = set(baseline.get("pids", []))
        current_pids = set(current.get("pids", []))

        findings["new_modules"] = sorted(list(current_modules - baseline_modules))
        findings["missing_modules"] = sorted(list(baseline_modules - current_modules))

        findings["new_pids"] = sorted(list(current_pids - baseline_pids))
        findings["missing_pids"] = sorted(list(baseline_pids - current_pids))

        findings["pid_change_count"] = len(findings["new_pids"]) + len(findings["missing_pids"])

        if findings["pid_change_count"] > 50:
            findings["pid_alert"] = True

        return findings