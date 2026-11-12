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
# ---- teaser message (parts are mixed randomly so no two posts look alike) ----
OPENERS = [
    "سلام دوستان 👋",
    "هی رفقا 😎",
    "وقتتون بخیر عزیزان ✨",
    "سلام به همه‌ی همراهان جت 🚀",
    "چطورید جماعت؟ 😄",
    "ببینم کی اینجاست؟ 👀",
    "سلام سلام 🙌",
    "رفقا یه لحظه حواستون به من باشه 📢",
]

QUESTIONS = [
    "آماده‌اید تا کانفیگ‌های جدید و پرسرعت رو براتون قرار بدم؟ ⚡️",
    "کانفیگ‌های تازه و تست‌شده رسیدن؛ شما آماده‌اید؟ 🔥",
    "یه دسته کانفیگ سریع و خوش‌پینگ آماده کردم، حاضرید؟ 🚀",
    "کانفیگ‌های نو از زیر دست تست دراومدن! دلتون براشون تنگ نشده؟ 😍",
    "آماده‌اید برای یه دور اینترنت پرسرعت؟ 🏎",
    "دسته‌ی تازه‌ی کانفیگ‌های سریع آماده‌ی انتشاره، شما چطور؟ 💥",
    "کانفیگ‌های پرسرعت جدید رو تست کردم و جواب دادن؛ بذارمشون؟ 😉",
    "می‌خواید ببینید این دفعه چه کانفیگ‌های تازه و تیزی گیرم اومده؟ 🤩",
]

TIMINGS = [
    "تا {m} دقیقه‌ی دیگه می‌ذارمشون ⏳",
    "{m} دقیقه‌ی دیگه همین‌جان، جایی نرید! 👇",
    "چند دقیقه‌ی دیگه منتشر می‌شن، آماده باشید ⏰",
    "تا چند دقیقه‌ی دیگه توی کانال می‌بینیدشون 📡",
    "گوشی دستتون باشه، {m} دقیقه‌ی دیگه شروع می‌کنیم 📱",
    "یه کم صبر کنید، {m} دقیقه‌ی دیگه می‌رسن ⌛️",
]


def fa_digits(value):
    return str(value).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹"))


def build_teaser(minutes, last):
    """Random mix of opener + question + timing. The question and the timing
    line always differ from the previous teaser."""
    m = fa_digits(int(round(minutes)))
    for _ in range(30):
        opener = random.choice(OPENERS) if random.random() < 0.75 else ""
        question = random.choice(QUESTIONS)
        timing = random.choice(TIMINGS)
        if question != last.get("question") and timing != last.get("timing"):
            break
    text = "\n\n".join(p for p in (opener, question, timing.format(m=m)) if p)
    return text, {"question": question, "timing": timing}


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
