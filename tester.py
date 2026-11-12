import json, os, queue, random, re, socket, subprocess, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from statistics import median
from urllib.parse import quote, unquote, urlsplit, urlunsplit, parse_qs
import requests

from common import config_id, load_json, prune, save_json, state_path

SOURCES = [
    # "ordered": the file is already ranked (fastest first), so it is not shuffled.
    {"name": "0xRadikal-Free-v2ray-Configs", "tag": "RK", "ordered": True, "urls": [
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt"]},
]

# Fallback sources: NOT used while the primary SOURCES above produce passing
# configs. They are tried only in a run where no primary config passed the test.
FALLBACK_SOURCES = [
    {"name": "mehrtat-vless-collector", "tag": "ME", "urls": [
        "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt"]},
    {"name": "Bllare-V2ray-Configs", "tag": "BL", "urls": [
        "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/ALL.txt"]},
    {"name": "MatinGhanbari-v2ray-configs", "tag": "MG", "urls": [
        f"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub{i}.txt"
        for i in range(1, 40)]},
]

# ---- selection / pre-filter -------------------------------------------------
MAX_CANDIDATES = 800          # configs pulled from all sources per run
MAX_CONFIGS_PER_RUN = 200     # configs that get the full Xray test (after TCP check)
TCP_TIMEOUT = 4.0
TCP_WORKERS = 64
RETEST_FAILED_HOURS = 6       # a config that failed is not retried for this long

# ---- parallel testing --------------------------------------------------------
WORKERS = int(os.environ.get("TEST_WORKERS", "8"))   # parallel Xray instances
BASE_PORT = 10808                                    # worker i uses BASE_PORT + i
SPEED_CONCURRENCY = 3         # speed tests that may download at the same time
SPEED_SEM = threading.Semaphore(SPEED_CONCURRENCY)

# ---- stability ---------------------------------------------------------------
STABILITY_ROUNDS = 2          # extra fresh-Xray rounds after the full test
STABILITY_GAP_SECONDS = 3
SOURCE_STATS_DECAY = 0.98     # per run; keeps ~6 hours of memory at a 10 min cadence

XRAY = "./bin/xray"
XRAY_VERSION = "26.2.6"
SOCKS_HOST, SOCKS_PORT = "127.0.0.1", BASE_PORT
MIN_SPEED_MBPS, MAX_LATENCY_MS = 5.0, 300.0
STABILITY_LATENCY_MS = MAX_LATENCY_MS * 1.5
LATENCY_URL = "https://www.gstatic.com/generate_204"
IP_CHECK_URL = "https://api.ipify.org"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=5000000"
RESULT_FILE = "passed_configs.json"
CHANNEL_LABEL = "تلگرام: @IRJetConfig"
SUPPORTED = {"raw", "tcp", "ws", "websocket", "grpc", "xhttp", "splithttp", "httpupgrade"}

FAILED_FILE = state_path("failed.json")
STATS_FILE = state_path("source_stats.json")
GEO_FILE = state_path("geo_cache.json")
GEO_TTL_SECONDS = 14 * 24 * 3600

FLAGS = {"DE":"🇩🇪","NL":"🇳🇱","FI":"🇫🇮","FR":"🇫🇷","GB":"🇬🇧","US":"🇺🇸","CA":"🇨🇦","CH":"🇨🇭","SE":"🇸🇪","NO":"🇳🇴","AT":"🇦🇹","PL":"🇵🇱","TR":"🇹🇷","RU":"🇷🇺","UA":"🇺🇦","RO":"🇷🇴","BG":"🇧🇬","CZ":"🇨🇿","JP":"🇯🇵","SG":"🇸🇬","HK":"🇭🇰","KR":"🇰🇷","IN":"🇮🇳","BR":"🇧🇷","AU":"🇦🇺","ES":"🇪🇸","IT":"🇮🇹","BE":"🇧🇪","IE":"🇮🇪","AE":"🇦🇪","IL":"🇮🇱"}
NAMES = {"DE":"Germany","NL":"Netherlands","FI":"Finland","FR":"France","GB":"United Kingdom","US":"United States","CA":"Canada","CH":"Switzerland","SE":"Sweden","NO":"Norway","AT":"Austria","PL":"Poland","TR":"Türkiye","RU":"Russia","UA":"Ukraine","RO":"Romania","BG":"Bulgaria","CZ":"Czechia","JP":"Japan","SG":"Singapore","HK":"Hong Kong","KR":"South Korea","IN":"India","BR":"Brazil","AU":"Australia","ES":"Spain","IT":"Italy","BE":"Belgium","IE":"Ireland","AE":"UAE","IL":"Israel"}

def first(p, *keys, default=""):
    for k in keys:
        v = p.get(k)
        if v and v[0] != "": return v[0]
    return default

def _decode_b64(value):
    import base64
    value = value.strip()
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode()).decode("utf-8-sig")

def _stream_settings(p, host):
    net = str(p.get("net", p.get("type", p.get("network", "tcp"))) or "tcp").lower()
    if net not in SUPPORTED: raise ValueError("Unsupported transport")
    method = {"tcp":"raw", "ws":"websocket", "splithttp":"xhttp"}.get(net, net)
    security = str(p.get("tls", p.get("security", "none")) or "none").lower()
    if security in ("true", "1"): security = "tls"
    if security not in ("none", "tls", "reality"): raise ValueError("Unsupported security")
    if security == "reality" and method not in ("raw", "xhttp", "grpc"):
        raise ValueError("REALITY cannot be combined with this transport")
    stream = {"network": method, "security": security}
    path = p.get("path", "/") or "/"
    host_header = p.get("host", host) or host
    if method == "raw":
        header_type = p.get("headerType", "none") or "none"
        raw = {}
        if str(header_type).lower() == "http":
            raw["header"] = {"type":"http", "request":{"path":[path],"headers":{"Host":[host_header]}}}
        stream["rawSettings"] = raw
    elif method == "websocket":
        stream["wsSettings"] = {"path":path,"headers":{"Host":host_header}}
    elif method == "grpc":
        grpc = {"serviceName":p.get("serviceName", p.get("service_name", "")) or "", "multiMode":str(p.get("mode", "gun")).lower()=="multi"}
        if p.get("authority"): grpc["authority"] = p["authority"]
        stream["grpcSettings"] = grpc
    elif method == "xhttp":
        xhttp = {"path":path,"mode":p.get("mode", "auto") or "auto"}
        if host_header: xhttp["host"] = host_header
        stream["xhttpSettings"] = xhttp
    elif method == "httpupgrade":
        stream["httpupgradeSettings"] = {"path":path,"host":host_header}
    if security == "tls":
        tls = {"serverName":p.get("sni", p.get("servername", host)) or host,
               "allowInsecure":str(p.get("allowInsecure", p.get("insecure", "0"))).lower() in ("1","true","yes")}
        alpn = p.get("alpn")
        if alpn: tls["alpn"] = [x for x in str(alpn).split(",") if x]
        fp = p.get("fp")
        if fp: tls["fingerprint"] = fp
        stream["tlsSettings"] = tls
    elif security == "reality":
        pbk = p.get("pbk", p.get("publicKey"))
        if not pbk: raise ValueError("REALITY public key missing")
        stream["realitySettings"] = {"serverName":p.get("sni", p.get("servername", host)) or host,
            "fingerprint":p.get("fp", "chrome") or "chrome", "password":pbk,
            "shortId":p.get("sid", "") or "", "spiderX":p.get("spx", "/") or "/"}
    return stream

def parse_config(uri, socks_port=SOCKS_PORT):
    u = urlsplit(uri); protocol = u.scheme.lower()
    if protocol == "vmess":
        raw = u.netloc or u.path
        data = json.loads(_decode_b64(raw))
        host = data.get("add") or data.get("host")
        port = int(data.get("port", 0))
        uuid = data.get("id", "")
        if not host or not port or not uuid: raise ValueError("Invalid VMess fields")
        p = {k:data.get(k) for k in ("net","type","host","path","tls","sni","alpn","fp","serviceName","mode","authority") if data.get(k) is not None}
        stream = _stream_settings(p, host)
        user = {"id":uuid,"alterId":int(data.get("aid", 0) or 0),"security":data.get("scy", "auto") or "auto"}
        outbound = {"protocol":"vmess","settings":{"vnext":[{"address":host,"port":port,"users":[user]}]},"streamSettings":stream}
    elif protocol == "ss":
        raw = u.netloc
        if "@" not in raw:
            decoded = _decode_b64(raw.split("#",1)[0])
            if "@" not in decoded: raise ValueError("Invalid Shadowsocks URI")
            raw = decoded
        userinfo, endpoint = raw.rsplit("@",1)
        if ":" not in endpoint: raise ValueError("Invalid Shadowsocks endpoint")
        host, port_text = endpoint.rsplit(":",1)
        port = int(port_text)
        if userinfo.startswith("["):
            userinfo = _decode_b64(userinfo[1:-1])
        elif ":" not in userinfo:
            userinfo = _decode_b64(userinfo)
        method, password = userinfo.split(":",1)
        if not host or not password: raise ValueError("Invalid Shadowsocks credentials")
        outbound = {"protocol":"shadowsocks","settings":{"servers":[{"address":host,"port":port,"method":method,"password":password}]}}
    elif protocol in ("vless", "trojan"):
        p = {k:v[0] for k,v in parse_qs(u.query, keep_blank_values=True).items() if v}
        if not u.hostname or not u.port: raise ValueError("Invalid server address")
        host, port, credential = u.hostname, u.port, unquote(u.username or "")
        stream = _stream_settings(p, host)
        if protocol == "vless":
            if not credential: raise ValueError("VLESS UUID missing")
            user = {"id":credential,"encryption":p.get("encryption", "none") or "none"}
            if p.get("flow"): user["flow"] = p["flow"]
            outbound = {"protocol":"vless","settings":{"vnext":[{"address":host,"port":port,"users":[user]}]},"streamSettings":stream}
        else:
            if not credential: raise ValueError("Trojan password missing")
            if stream["security"] == "none": raise ValueError("Trojan without TLS/REALITY rejected")
            outbound = {"protocol":"trojan","settings":{"servers":[{"address":host,"port":port,"password":credential}]},"streamSettings":stream}
    else:
        raise ValueError("Unsupported protocol")
    return {"log":{"loglevel":"warning"},"inbounds":[{"listen":SOCKS_HOST,"port":socks_port,"protocol":"socks","settings":{"auth":"noauth","udp":False}}],"outbounds":[outbound,{"protocol":"freedom","tag":"direct"}]}


def wait_for_xray(proc, port):
    for _ in range(50):
        if proc.poll() is not None: return False
        try:
            with socket.create_connection((SOCKS_HOST, port), timeout=1) as s:
                s.settimeout(1); s.sendall(b"\x05\x01\x00")
                if s.recv(2) == b"\x05\x00": return True
        except OSError: time.sleep(.2)
    return False

def proxies(port):
    px = f"socks5h://{SOCKS_HOST}:{port}"
    return {"http": px, "https": px}

def check_tunnel(px):
    r = requests.get(IP_CHECK_URL, proxies=px, timeout=(8, 15)); r.raise_for_status()
    ip = r.text.strip()
    if not re.fullmatch(r"[0-9a-fA-F:.]+", ip): raise ValueError("Invalid proxy IP response")
    return ip

def latency(px):
    start = time.perf_counter()
    r = requests.get(LATENCY_URL, proxies=px, timeout=(8, 15), headers={"Cache-Control": "no-cache"})
    if r.status_code not in (200, 204): raise ValueError("Latency endpoint rejected request")
    return (time.perf_counter() - start) * 1000

def speed(px):
    start = time.perf_counter(); total = 0
    with requests.get(SPEED_URL, proxies=px, timeout=(10, 35), stream=True, headers={"Cache-Control": "no-cache"}) as r:
        r.raise_for_status()
        for chunk in r.iter_content(65536):
            if chunk:
                total += len(chunk)
                if total >= 5_000_000: break
    elapsed = time.perf_counter() - start
    if total < 4_000_000 or elapsed <= 0: raise ValueError("Incomplete speed test")
    return total * 8 / elapsed / 1_000_000

# ---- GeoIP: several providers, 2 must agree, verified answers cached ---------
GEO_PROVIDERS = [
    ("ipwho.is", lambda ip: f"https://ipwho.is/{ip}",
     lambda d: d.get("country_code") if d.get("success") else None),
    ("ipapi.co", lambda ip: f"https://ipapi.co/{ip}/json/",
     lambda d: None if d.get("error") else d.get("country_code")),
    ("country.is", lambda ip: f"https://api.country.is/{ip}",
     lambda d: d.get("country")),
    ("ipinfo.io", lambda ip: f"https://ipinfo.io/{ip}/json",
     lambda d: d.get("country")),
]
GEO_CACHE = {}            # ip -> {"cc": "DE", "ts": 1700000000}
_GEO_LOCK = threading.Lock()

def country_lookup(exit_ip):
    """GeoIP of the real tunnel exit IP. A flag is asserted only when two
    independent providers agree; verified answers are cached between runs."""
    with _GEO_LOCK:
        hit = GEO_CACHE.get(exit_ip)
    if hit and time.time() - hit["ts"] < GEO_TTL_SECONDS:
        return {"country_code": hit["cc"], "verified": True, "providers": 0, "cached": True}
    votes, answered = {}, 0
    headers = {"User-Agent": "JetConfigTester/3.1"}
    for _name, build_url, extract in GEO_PROVIDERS:
        try:
            r = requests.get(build_url(exit_ip), timeout=6, headers=headers)
            r.raise_for_status()
            code = extract(r.json())
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            continue
        if not code or not isinstance(code, str) or len(code) != 2:
            continue
        code = code.upper(); answered += 1
        votes[code] = votes.get(code, 0) + 1
        if votes[code] >= 2:
            with _GEO_LOCK:
                GEO_CACHE[exit_ip] = {"cc": code, "ts": time.time()}
            return {"country_code": code, "verified": True, "providers": answered}
    return {"country_code": "", "verified": False, "providers": answered,
            "reported_codes": list(votes)}

def renamed_uri(uri, exit_ip, source_tag):
    # GeoIP is based on the actual public IP seen through the tunnel,
    # never on the config server hostname. Disagreement means no country flag.
    # Only the flag is shown, so the channel name stays prominent in the client.
    u = urlsplit(uri)
    geo = country_lookup(exit_ip)
    cc = geo["country_code"]
    flag = FLAGS.get(cc, "🌐") if geo["verified"] else "🌐"
    label = f"{flag} | {CHANNEL_LABEL} #{source_tag}"
    return urlunsplit((u.scheme, u.netloc, u.path, u.query, quote(label, safe=""))), geo

# ---- TCP pre-check ------------------------------------------------------------
def endpoint_of(cfg):
    settings = cfg["outbounds"][0]["settings"]
    entry = settings["vnext"][0] if "vnext" in settings else settings["servers"][0]
    return entry["address"], int(entry["port"])

def tcp_alive(item):
    """True when the config parses, uses a supported transport and its server
    port accepts a TCP connection. Costs ~ms instead of a full Xray round."""
    uri, _tag = item
    try:
        host, port = endpoint_of(parse_config(uri))
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return False

# ---- one Xray round -----------------------------------------------------------
@contextmanager
def xray_session(uri, port, info):
    tmpdir = tempfile.mkdtemp(prefix="xray_")
    log = tempfile.TemporaryFile()
    proc = None
    try:
        info["phase"] = "parse"
        cfg = parse_config(uri, port)
        path = os.path.join(tmpdir, "config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)

        info["phase"] = "config_validation"
        validation = subprocess.run([XRAY, "run", "-test", "-c", path],
                                    capture_output=True, text=True, timeout=15)
        if validation.returncode != 0:
            details = (validation.stderr or validation.stdout or "").splitlines()
            raise RuntimeError(details[-1][:180] if details else "Xray config validation failed")

        info["phase"] = "xray_start"
        proc = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=log)
        if not wait_for_xray(proc, port):
            log.seek(0)
            detail = log.read().decode("utf-8", errors="replace").splitlines()
            raise RuntimeError(" | ".join(line[:160] for line in detail[-3:]) or "Xray did not start")
        yield proxies(port)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=4)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)
        log.close()
        try:
            for name in os.listdir(tmpdir): os.remove(os.path.join(tmpdir, name))
            os.rmdir(tmpdir)
        except OSError: pass

def run_round(uri, port, info, full):
    """Returns (exit_ip, latency_ms, speed_mbps|None) or None when the config
    is too slow. Raises on any connectivity error."""
    with xray_session(uri, port, info) as px:
        info["phase"] = "tunnel_check"; exit_ip = check_tunnel(px)
        info["phase"] = "latency"; ms = latency(px)
        if ms > (MAX_LATENCY_MS if full else STABILITY_LATENCY_MS): return None
        mbps = None
        if full:
            info["phase"] = "speed"
            with SPEED_SEM:
                mbps = speed(px)
            if mbps < MIN_SPEED_MBPS: return None
        return exit_ip, ms, mbps

def test_config(uri, source_tag, port):
    """Full test, then STABILITY_ROUNDS extra rounds with a fresh Xray each.
    Only configs that pass every round are returned."""
    info = {"phase": "parse"}
    try:
        first_round = run_round(uri, port, info, full=True)
        if first_round is None: return None
        exit_ip, ms, mbps = first_round
        latencies = [ms]
        for n in range(1, STABILITY_ROUNDS + 1):
            time.sleep(STABILITY_GAP_SECONDS)
            info["phase"] = f"stability_{n}"
            again = run_round(uri, port, info, full=False)
            if again is None: return None
            latencies.append(again[1])
        renamed, geo = renamed_uri(uri, exit_ip, source_tag)
        return {"config": renamed,
                "country_code": geo["country_code"],
                "country_verified": geo["verified"],
                "geoip_providers": geo["providers"],
                "geoip_reported_codes": geo.get("reported_codes", []),
                "latency_ms": round(median(latencies), 2),
                "speed_mbps": round(mbps, 2),
                "rounds_ok": 1 + STABILITY_ROUNDS}
    except Exception as e:
        # Never log the full URI or credentials.
        print(f"Test failed during {info['phase']}: {type(e).__name__}: {str(e)[:150]}")
        return None

# ---- sources ------------------------------------------------------------------
def extract_subscription_lines(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    accepted = ("vless://", "vmess://", "trojan://", "ss://")
    direct = [line for line in lines if line.lower().startswith(accepted)]
    if direct:
        return direct
    # Some subscription endpoints return one Base64-encoded text blob.
    compact = "".join(lines)
    if compact and not compact.startswith(("#", "{")):
        try:
            decoded = _decode_b64(compact)
            return [line.strip() for line in decoded.splitlines()
                    if line.strip().lower().startswith(accepted)]
        except Exception:
            pass
    return []

def fetch_source(source):
    collected = []
    for index, url in enumerate(source["urls"], 1):
        try:
            response = requests.get(url, timeout=(5, 12),
                headers={"User-Agent": "JetConfigTester/3.1"})
            response.raise_for_status()
            found = extract_subscription_lines(response.text)
            if found:
                collected.extend(found)
                print(f"Source {source['name']} [{index}/{len(source['urls'])}]: {len(found)} configs")
            else:
                print(f"Source {source['name']} [{index}/{len(source['urls'])}]: empty/unsupported")
        except requests.RequestException as exc:
            print(f"Source {source['name']} [{index}/{len(source['urls'])}] skipped: {type(exc).__name__}")
            continue
    return list(dict.fromkeys(collected))

def source_rates(tags, stats, prior=0.03, strength=50):
    """Smoothed pass rate per source (Bayesian prior keeps new sources neutral)."""
    rates = {}
    for tag in tags:
        s = stats.get(tag, {})
        rates[tag] = (s.get("passed", 0.0) + prior * strength) / (s.get("tested", 0.0) + strength)
    return rates

def allocate(items_by_tag, budget, stats):
    """Split the candidate budget between sources in proportion to their recent
    pass rate. Every source keeps at least 25% of the average weight, so a
    source that had a bad hour can recover. Unused quota is redistributed."""
    tags = list(items_by_tag)
    rates = source_rates(tags, stats)
    mean = sum(rates.values()) / len(rates) if rates else 0
    weights = {t: max(rates[t], 0.25 * mean) for t in tags}
    alloc = {t: 0 for t in tags}
    active = [t for t in tags if items_by_tag[t]]
    remaining = budget
    while remaining > 0 and active:
        total = sum(weights[t] for t in active)
        given = 0
        for t in active:
            share = max(1, int(remaining * weights[t] / total))
            give = min(share, len(items_by_tag[t]) - alloc[t], remaining - given)
            alloc[t] += give; given += give
        remaining -= given
        active = [t for t in active if alloc[t] < len(items_by_tag[t])]
        if given == 0: break
    return alloc

def interleave(selected):
    """Round-robin across sources: [(tag, [uri...])] -> [(uri, tag)...]"""
    ordered, depth = [], max((len(v) for _, v in selected), default=0)
    for i in range(depth):
        for tag, items in selected:
            if i < len(items): ordered.append((items[i], tag))
    return ordered

def run_stage(name, sources, failed, stats, now):
    """Fetch -> quota -> TCP check -> full/stability test for one group of sources.
    `failed` and `stats` are updated in place."""
    print(f"=== Stage: {name} ===")
    items_by_tag = {}
    for source in sources:
        items = fetch_source(source)
        fresh = [u for u in items if config_id(u) not in failed]
        if not source.get("ordered"):
            random.shuffle(fresh)       # a different slice of the pool every run
        items_by_tag[source["tag"]] = fresh
        print(f"Source total {source['name']}: {len(items)} unique, {len(fresh)} not recently failed")

    alloc = allocate(items_by_tag, MAX_CANDIDATES, stats)
    print("Candidate quota: " + ", ".join(f"{t}={n}" for t, n in alloc.items()))
    selected = [(t, items_by_tag[t][:alloc[t]]) for t in items_by_tag]
    candidates, seen = [], set()
    for uri, tag in interleave(selected):
        if uri not in seen:
            seen.add(uri); candidates.append((uri, tag))

    # Stage 1: cheap TCP check on every candidate.
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        alive_flags = list(pool.map(tcp_alive, candidates))
    alive = [c for c, ok in zip(candidates, alive_flags) if ok]
    tcp_dead = [c for c, ok in zip(candidates, alive_flags) if not ok]
    to_test, skipped = alive[:MAX_CONFIGS_PER_RUN], alive[MAX_CONFIGS_PER_RUN:]
    print(f"TCP pre-check: {len(alive)}/{len(candidates)} reachable | "
          f"full test: {len(to_test)} (limit {MAX_CONFIGS_PER_RUN}), left for later: {len(skipped)}")

    # Stage 2: full + stability test in parallel, one SOCKS port per worker.
    ports = queue.Queue()
    for i in range(WORKERS): ports.put(BASE_PORT + i)

    def worker(item):
        uri, tag = item
        port = ports.get()
        try: return test_config(uri, tag, port)
        finally: ports.put(port)

    passed, passed_by_tag, tested_by_tag = [], {}, {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(worker, item): item for item in to_test}
        done = 0
        for fut in as_completed(futures):
            uri, tag = futures[fut]
            done += 1
            tested_by_tag[tag] = tested_by_tag.get(tag, 0) + 1
            try: result = fut.result()
            except Exception as exc:
                print(f"Worker error: {type(exc).__name__}"); result = None
            if result:
                passed.append(result)
                passed_by_tag[tag] = passed_by_tag.get(tag, 0) + 1
                print(f"{done}/{len(to_test)} PASS [{tag}] | {result['latency_ms']} ms | {result['speed_mbps']} Mbps")
            else:
                failed[config_id(uri)] = now
                print(f"{done}/{len(to_test)} FAIL [{tag}]")
    for uri, tag in tcp_dead:
        failed[config_id(uri)] = now
        tested_by_tag[tag] = tested_by_tag.get(tag, 0) + 1

    for tag in items_by_tag:
        old = stats.get(tag, {"tested": 0.0, "passed": 0.0})
        stats[tag] = {"tested": old["tested"] * SOURCE_STATS_DECAY + tested_by_tag.get(tag, 0),
                      "passed": old["passed"] * SOURCE_STATS_DECAY + passed_by_tag.get(tag, 0)}

    print("Source pass rates: " + ", ".join(
        f"{t}={passed_by_tag.get(t, 0)}/{tested_by_tag.get(t, 0)}" for t in items_by_tag))
    return {"passed": passed, "tested": len(to_test), "tcp_dead": len(tcp_dead)}

def main():
    print(f"Jet Config Tester | target Xray {XRAY_VERSION} | workers {WORKERS}")
    now = time.time()
    failed = prune(load_json(FAILED_FILE, {}), RETEST_FAILED_HOURS * 3600, now)
    stats = load_json(STATS_FILE, {})
    for ip, entry in load_json(GEO_FILE, {}).items():
        if isinstance(entry, dict) and now - entry.get("ts", 0) < GEO_TTL_SECONDS:
            GEO_CACHE[ip] = entry

    stage = run_stage("primary", SOURCES, failed, stats, now)
    passed, tested, tcp_dead = stage["passed"], stage["tested"], stage["tcp_dead"]

    # Fallback sources only when nothing from the primary sources passed.
    if not passed and FALLBACK_SOURCES:
        print("No config from the primary sources passed -> trying the fallback sources.")
        fallback = run_stage("fallback", FALLBACK_SOURCES, failed, stats, now)
        passed += fallback["passed"]
        tested += fallback["tested"]
        tcp_dead += fallback["tcp_dead"]

    # Persist results and state.
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(passed, f, ensure_ascii=False, indent=2)
    try: os.chmod(RESULT_FILE, 0o600)
    except OSError: pass
    save_json(FAILED_FILE, failed)
    save_json(STATS_FILE, stats)
    save_json(GEO_FILE, GEO_CACHE)

    print(f"Total full-tested: {tested} | TCP-dead: {tcp_dead} | Passed (all {1 + STABILITY_ROUNDS} rounds): {len(passed)}")
    print("Supported tested protocols: VLESS, VMess, Trojan, Shadowsocks. SSR/TUIC/Hysteria2 and unsupported transports are skipped.")

if __name__ == "__main__": main()
