from scanner import ScannerAgent
from baseline import BaselineManager
from anomaly_detector import AnomalyDetector
from pattern_agent import RootkitPatternAgent
from report_agent import ReportAgent

scanner = ScannerAgent()
baseline_manager = BaselineManager()
anomaly_detector = AnomalyDetector()
pattern_agent = RootkitPatternAgent()
report_agent = ReportAgent()

current_snapshot = scanner.collect_snapshot()
baseline = baseline_manager.load_baseline()

if baseline is None:
    print("No baseline found. Saving current snapshot as baseline...")
    baseline_manager.save_baseline(current_snapshot)
    print("Baseline saved!")
else:
    print("Running full MAKIM analysis...\n")

    anomaly_findings = anomaly_detector.compare(baseline, current_snapshot)
    pattern_findings = pattern_agent.analyze(current_snapshot)

    report = report_agent.generate_report(
        current_snapshot,
        anomaly_findings,
        pattern_findings
    )

    report_agent.print_report(report)

    path = report_agent.save_report(report)
    print(f"Report saved to: {path}")