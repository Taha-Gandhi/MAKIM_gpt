import os
import subprocess
from datetime import datetime


class ScannerAgent:
    """
    ScannerAgent collects raw system data from Linux user space.
    For version 1, it reads:
    - loaded kernel modules from /proc/modules
    - running PIDs from /proc
    - recent dmesg output
    """

    def get_loaded_modules(self):
        modules = []

        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if parts:
                        modules.append(parts[0])
        except Exception as e:
            modules.append(f"ERROR_READING_MODULES: {str(e)}")

        return sorted(modules)

    def get_running_pids(self):
        pids = []

        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    pids.append(int(entry))
        except Exception as e:
            return [f"ERROR_READING_PIDS: {str(e)}"]

        return sorted(pids)

    def get_dmesg_output(self, lines=50):
        """
        Reads the latest kernel messages.
        This may require elevated permissions depending on system config.
        """
        try:
            result = subprocess.run(
                ["dmesg", "--color=never"],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                return [f"DMESG_UNAVAILABLE: {result.stderr.strip()}"]

            output_lines = result.stdout.strip().splitlines()
            return output_lines[-lines:]
        except Exception as e:
            return [f"ERROR_READING_DMESG: {str(e)}"]

    def collect_snapshot(self):
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "modules": self.get_loaded_modules(),
            "pids": self.get_running_pids(),
            "dmesg_tail": self.get_dmesg_output(),
        }