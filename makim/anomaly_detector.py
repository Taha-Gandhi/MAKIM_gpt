class AnomalyDetector:

    def compare(self, baseline, current):
        findings = {
            "new_modules": [],
            "missing_modules": [],
            "new_pids": [],
            "missing_pids": [],
        }

        baseline_modules = set(baseline.get("modules", []))
        current_modules = set(current.get("modules", []))

        baseline_pids = set(baseline.get("pids", []))
        current_pids = set(current.get("pids", []))

        findings["new_modules"] = list(current_modules - baseline_modules)
        findings["missing_modules"] = list(baseline_modules - current_modules)

        findings["new_pids"] = list(current_pids - baseline_pids)
        findings["missing_pids"] = list(baseline_pids - current_pids)

        return findings