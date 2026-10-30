import os
import json
import sys
import requests

RESULT_FILE = "passed_configs.json"

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

    payload = {
        "secret": APPS_SCRIPT_SECRET,
        "configs": configs
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

        print("Publication request completed.")
        print("Passing configurations:", result.get("received", 0))
        print("Telegram messages sent:", result.get("sent", 0))

    except requests.RequestException as error:
        print("ERROR: Could not contact Apps Script.")
        print(str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
