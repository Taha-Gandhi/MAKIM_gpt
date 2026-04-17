import os
import subprocess
from datetime import datetime


class ScannerAgent:

    def get_loaded_modules(self):
        modules = []
        try:
            with open("/proc/modules", "r") as f:
                for line in f:
                    modules.append(line.split()[0])
        except Exception as e:
            modules.append(f"ERROR: {str(e)}")
        return sorted(modules)

    def get_running_pids(self):
        try:
            return sorted([int(pid) for pid in os.listdir("/proc") if pid.isdigit()])
        except Exception as e:
            return [f"ERROR: {str(e)}"]

    def get_dmesg_output(self):
        try:
            output = subprocess.check_output(["dmesg", "--color=never"], text=True)
            return output.splitlines()[-50:]
        except Exception as e:
            return [f"ERROR: {str(e)}"]

    def get_process_maps_summary(self, max_pids=20):
        summaries = []

        pids = self.get_running_pids()

        if not pids or isinstance(pids[0], str):
            return []

        for pid in pids[:max_pids]:
            try:
                with open(f"/proc/{pid}/maps", "r", errors="ignore") as f:
                    lines = f.readlines()

                suspicious_regions = 0

                for line in lines:
                    parts = line.split()

                    if len(parts) >= 2:
                        perms = parts[1]
                        pathname = parts[-1] if len(parts) >= 6 else ""

                        if "x" in perms and (pathname == "" or pathname.startswith("[")):
                            suspicious_regions += 1

                summaries.append({
                    "pid": pid,
                    "suspicious_regions": suspicious_regions
                })

            except:
                continue

        return summaries

    def collect_snapshot(self):
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "modules": self.get_loaded_modules(),
            "pids": self.get_running_pids(),
            "dmesg_tail": self.get_dmesg_output(),
            "process_maps_summary": self.get_process_maps_summary()
        }