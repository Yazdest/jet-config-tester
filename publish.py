import os
import json
import random
import sys
import time
import requests

from common import config_id, load_json, prune, save_json, state_path

RESULT_FILE = "passed_configs.json"
SENT_FILE = state_path("sent.json")
TEASER_FILE = state_path("teaser.json")

# A config that was already published is not sent again for this many hours.
SENT_TTL_HOURS = float(os.environ.get("SENT_TTL_HOURS", "10"))
# Minutes between the teaser message and the configs.
TEASER_DELAY_MINUTES = float(os.environ.get("TEASER_DELAY_MINUTES", "5"))

APPS_SCRIPT_URL = os.environ.get("APPS_SCRIPT_URL")
APPS_SCRIPT_SECRET = os.environ.get("APPS_SCRIPT_SECRET")
# ---- teaser message ----------------------------------------------------------
# One short line: the main point comes first (it is what shows in the phone
# notification), then a short timing hint. Parts are mixed randomly.
HOOKS = [
    "کانفیگ‌های سریع و پرسرعت رسیدن، آماده‌اید؟ ⚡️",
    "یه دسته کانفیگ تست‌شده با سرعت بالا آماده‌ست 🚀",
    "سرعت‌های بالا داره میاد، آماده‌اید؟ 🔥",
    "کانفیگ‌های فوق‌سریع جدید آماده شدن 🏎",
    "کانفیگ‌هایی که سرعتشون حرف نداره آماده‌ست 💥",
    "سرعت اینترنتتون رو بالا ببرید، کانفیگ‌های سریع میان ⚡️",
    "کانفیگ‌های تند و تیز با پینگ پایین رسیدن 😍",
    "جدیدترین کانفیگ‌های پرسرعت تست شدن و عالی بودن 😉",
    "آماده‌اید برای اینترنت سریع و بی‌وقفه؟ 🤩",
    "کانفیگ‌های پرسرعت و کم‌پینگ آماده‌ی انتشارن 📡",
]

TIMINGS = [
    "{m} دقیقه‌ی دیگه اینجاست ⏳",
    "تا {m} دقیقه‌ی دیگه 👇",
    "جایی نرید، {m} دقیقه‌ی دیگه ⏰",
    "چند دقیقه‌ی دیگه منتشر می‌شن 📣",
    "{m} دقیقه‌ی دیگه توی کانال 📺",
    "گوشی دستتون، {m} دقیقه‌ی دیگه 📱",
    "فقط {m} دقیقه صبر کنید ⌛️",
    "{m} دقیقه‌ی دیگه شروع می‌کنیم 🚦",
]


def fa_digits(value):
    return str(value).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹"))


def build_teaser(minutes, last):
    """Single-line teaser: hook + timing. Both differ from the previous one."""
    m = fa_digits(int(round(minutes)))
    for _ in range(30):
        hook = random.choice(HOOKS)
        timing = random.choice(TIMINGS)
        if hook != last.get("hook") and timing != last.get("timing"):
            break
    return f"{hook} {timing.format(m=m)}", {"hook": hook, "timing": timing}


def send_teaser(text):
    """Ask Apps Script to post the teaser (it holds the bot token)."""
    try:
        response = requests.post(
            APPS_SCRIPT_URL,
            json={"secret": APPS_SCRIPT_SECRET, "action": "teaser", "text": text},
            timeout=60,
            allow_redirects=True,
        )
        response.raise_for_status()
        result = response.json()
        if not result.get("ok"):
            print("WARNING: teaser rejected by Apps Script:", result.get("error", "Unknown error"))
            return False
        return True
    except (requests.RequestException, ValueError) as error:
        print(f"WARNING: teaser not sent ({type(error).__name__}).")
        return False


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

    # Teaser first, then wait so the audience has time to get curious.
    last = load_json(TEASER_FILE, {})
    text, picked = build_teaser(TEASER_DELAY_MINUTES, last)
    if send_teaser(text):
        save_json(TEASER_FILE, picked)
        print(f"Teaser sent. Waiting {TEASER_DELAY_MINUTES:g} minutes before publishing...")
        sys.stdout.flush()
        time.sleep(TEASER_DELAY_MINUTES * 60)

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
        sent_at = time.time()
        for config in new_configs:
            sent[config_id(config)] = sent_at
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
