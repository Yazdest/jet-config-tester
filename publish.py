import os
import json
import sys
import time
import requests

from common import config_id, load_json, prune, save_json, state_path

RESULT_FILE = "passed_configs.json"
SENT_FILE = state_path("sent.json")
# A config that was already published is not sent again for this many hours.
SENT_TTL_HOURS = float(os.environ.get("SENT_TTL_HOURS", "8"))

APPS_SCRIPT_URL = os.environ.get("APPS_SCRIPT_URL")
APPS_SCRIPT_SECRET = os.environ.get("APPS_SCRIPT_SECRET")


def main():
    if not APPS_SCRIPT_URL or not APPS_SCRIPT_SECRET:
        print("ERROR: GitHub secrets are missing.")
        sys.exit(1)

    if not os.path.exists(RESULT_FILE):
        print("ERROR: Test results file not found.")
        sys.exit(1)

    with open(RESULT_FILE, "r", encoding="utf-8") as file:
        results = json.load(file)

    configs = [
        item["config"]
        for item in results
        if isinstance(item, dict)
        and isinstance(item.get("config"), str)
    ]

    if not configs:
        print("No configurations passed the tests. Nothing to publish.")
        return

    # Skip configs that were already published recently.
    now = time.time()
    sent = prune(load_json(SENT_FILE, {}), SENT_TTL_HOURS * 3600, now)
    new_configs, new_ids = [], set()
    for config in configs:
        cid = config_id(config)
        if cid in sent or cid in new_ids:
            continue
        new_ids.add(cid)
        new_configs.append(config)

    print(f"Passed: {len(configs)} | already published recently: "
          f"{len(configs) - len(new_configs)} | new: {len(new_configs)}")

    if not new_configs:
        save_json(SENT_FILE, sent)   # keep the pruned history
        print("No new configurations to publish.")
        return

    payload = {
        "secret": APPS_SCRIPT_SECRET,
        "configs": new_configs
    }

    try:
        response = requests.post(
            APPS_SCRIPT_URL,
            json=payload,
            timeout=120,
            allow_redirects=True
        )

        response.raise_for_status()

        try:
            result = response.json()
        except ValueError:
            print("ERROR: Apps Script returned an invalid response.")
            sys.exit(1)

        if not result.get("ok"):
            print("ERROR: Apps Script rejected the request.")
            print(result.get("error", "Unknown error"))
            sys.exit(1)

        # Only after a confirmed success are the configs marked as published,
        # so a failed request is retried automatically on the next run.
        for config in new_configs:
            sent[config_id(config)] = now
        save_json(SENT_FILE, sent)

        print("Publication request completed.")
        print("Passing configurations:", result.get("received", 0))
        print("Telegram messages sent:", result.get("sent", 0))

    except requests.RequestException as error:
        print("ERROR: Could not contact Apps Script.")
        print(str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
