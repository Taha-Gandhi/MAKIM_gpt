import json
import os

BASELINE_FILE = "baseline/trusted_baseline.json"


class BaselineManager:

    def save_baseline(self, snapshot):
        os.makedirs("baseline", exist_ok=True)

        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)

    def load_baseline(self):
        if not os.path.exists(BASELINE_FILE):
            return None

        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)