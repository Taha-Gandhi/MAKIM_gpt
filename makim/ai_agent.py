class AIAgent:

    def explain(self, report):
        severity = report.get("severity", "UNKNOWN")
        anomalies = report.get("anomalies", {})
        patterns = report.get("patterns", {})

        explanation = []

        explanation.append(f"Overall system severity is {severity}.")

        if severity == "LOW":
            explanation.append("System appears stable with no significant threats detected.")

        if anomalies.get("pid_alert"):
            explanation.append("There is higher-than-normal process activity.")

        if patterns.get("suspicious_memory"):
            explanation.append("Some processes have unusual memory behavior.")

        if patterns.get("suspicious_dmesg"):
            explanation.append("Kernel logs show potentially concerning events.")

        if patterns.get("risk_score", 0) == 0:
            explanation.append("No strong indicators of compromise were found.")

        return " ".join(explanation)