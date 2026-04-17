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
            "suspicious_memory": [],
            "risk_score": 0
        }

        # --- Module check ---
        for module in snapshot.get("modules", []):
            if any(k in module.lower() for k in ["rootkit", "hide", "hook"]):
                findings["suspicious_modules"].append(module)
                findings["risk_score"] += 3

        # --- dmesg check (ignore normal AppArmor noise) ---
        for line in snapshot.get("dmesg_tail", []):
            line_lower = line.lower()

            if "apparmor" in line_lower:
                continue  # ignore normal security logs

            if any(k in line_lower for k in ["segfault", "exploit", "injection"]):
                findings["suspicious_dmesg"].append(line)
                findings["risk_score"] += 2

        # --- memory check (ignore system processes) ---
        for proc in snapshot.get("process_maps_summary", []):
            pid = proc.get("pid", 0)
            regions = proc.get("suspicious_regions", 0)

            if pid <= 100:  
                continue  # ignore system processes

            if regions > 1:
                findings["suspicious_memory"].append(proc)
                findings["risk_score"] += 2

        return findings