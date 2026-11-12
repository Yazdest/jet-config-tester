"""Shared helpers for tester.py and publish.py (persistent state between runs)."""
import hashlib, json, os, time

STATE_DIR = os.environ.get("STATE_DIR", "state")


def state_path(name):
    return os.path.join(STATE_DIR, name)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def config_id(uri):
    """Stable identity of a config: everything except the #remark.

    The remark is rewritten by the tester (flag / channel / tag), so it must
    not influence identity. Only a hash is stored, never the config itself.
    """
    base = uri.split("#", 1)[0].strip()
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:20]


def prune(history, max_age_seconds, now=None):
    """Drop entries older than max_age_seconds. history = {id: timestamp}."""
    now = time.time() if now is None else now
    return {k: v for k, v in history.items()
            if isinstance(v, (int, float)) and now - v < max_age_seconds}
