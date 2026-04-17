class RootkitPatternAgent:

    SUSPICIOUS_MODULE_KEYWORDS = [
        "rootkit",
        "hide",
        "stealth",
        "hook",
        "backdoor"
    ]

    SUSPICIOUS_DMESG_KEYWORDS = [
        "taint",
        "warning",
        "segfault",
        "denied",
        "hook"
    ]

    def analyze(self, snapshot):
        findings = {
            "suspicious_modules": [],
            "suspicious_dmesg": [],
            "risk_score": 0
        }

        # Check modules
        for module in snapshot.get("modules", []):
            module_str = str(module).lower()
            for keyword in self.SUSPICIOUS_MODULE_KEYWORDS:
                if keyword in module_str:
                    findings["suspicious_modules"].append(module)
                    findings["risk_score"] += 2
                    break

        # Check dmesg
        for line in snapshot.get("dmesg_tail", []):
            line_str = str(line).lower()
            for keyword in self.SUSPICIOUS_DMESG_KEYWORDS:
                if keyword in line_str:
                    findings["suspicious_dmesg"].append(line)
                    findings["risk_score"] += 1
                    break

        for proc in snapshot.get("process_maps_summary", []):
            if proc["suspicious_regions"] > 0:
                findings["suspicious_memory"].append(proc)
                findings["risk_score"] += 2

        return findings