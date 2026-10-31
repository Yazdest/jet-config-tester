import json, os, re, socket, subprocess, tempfile, time
from functools import lru_cache
from urllib.parse import quote, unquote, urlsplit, urlunsplit, parse_qs
import requests

SOURCES = [
    {
        "name": "mehrtat-vless-collector",
        "url": "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt",
    },
    {
        "name": "morpheusadam-v2ray-config",
        "url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    },
    {
        "name": "Idolvpn-Automate-V2ray-Config-Collector",
        "url": "https://raw.githubusercontent.com/Idolvpn/Automate-V2ray-Config-Collector/main/configs/vless.txt",
    },
    {
        "name": "Bllare-V2ray-Configs",
        "url": "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/ALL.txt",
    },
    {
        "name": "Farid-Karimi-Config-Collector",
        "url": "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/vless_iran.txt",
    },
    {
        "name": "miladtahanian-Config-Collector",
        "url": "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    },
]
MAX_CONFIGS_PER_RUN = 150
XRAY = "./bin/xray"
XRAY_VERSION = "26.2.6"
SOCKS_HOST, SOCKS_PORT = "127.0.0.1", 10808
MIN_SPEED_MBPS, MAX_LATENCY_MS = 5.0, 300.0
LATENCY_URL = "https://www.gstatic.com/generate_204"
IP_CHECK_URL = "https://api.ipify.org"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=5000000"
RESULT_FILE = "passed_configs.json"
CHANNEL_LABEL = "تلگرام: @IRJetConfig"
SUPPORTED = {"raw", "tcp", "ws", "websocket", "grpc", "xhttp", "splithttp", "httpupgrade"}
FLAGS = {"DE":"🇩🇪","NL":"🇳🇱","FI":"🇫🇮","FR":"🇫🇷","GB":"🇬🇧","US":"🇺🇸","CA":"🇨🇦","CH":"🇨🇭","SE":"🇸🇪","NO":"🇳🇴","AT":"🇦🇹","PL":"🇵🇱","TR":"🇹🇷","RU":"🇷🇺","UA":"🇺🇦","RO":"🇷🇴","BG":"🇧🇬","CZ":"🇨🇿","JP":"🇯🇵","SG":"🇸🇬","HK":"🇭🇰","KR":"🇰🇷","IN":"🇮🇳","BR":"🇧🇷","AU":"🇦🇺","ES":"🇪🇸","IT":"🇮🇹","BE":"🇧🇪","IE":"🇮🇪","AE":"🇦🇪","IL":"🇮🇱"}
NAMES = {"DE":"Germany","NL":"Netherlands","FI":"Finland","FR":"France","GB":"United Kingdom","US":"United States","CA":"Canada","CH":"Switzerland","SE":"Sweden","NO":"Norway","AT":"Austria","PL":"Poland","TR":"Türkiye","RU":"Russia","UA":"Ukraine","RO":"Romania","BG":"Bulgaria","CZ":"Czechia","JP":"Japan","SG":"Singapore","HK":"Hong Kong","KR":"South Korea","IN":"India","BR":"Brazil","AU":"Australia","ES":"Spain","IT":"Italy","BE":"Belgium","IE":"Ireland","AE":"UAE","IL":"Israel"}

def first(p, *keys, default=""):
    for k in keys:
        v = p.get(k)
        if v and v[0] != "": return v[0]
    return default

def parse_config(uri):
    u = urlsplit(uri); p = parse_qs(u.query, keep_blank_values=True)
    protocol = u.scheme.lower()
    if protocol not in ("vless", "trojan") or not u.hostname or not u.port:
        raise ValueError("Invalid URI or unsupported protocol")
    host, port, credential = u.hostname, u.port, unquote(u.username or "")
    net = first(p, "type", "network", default="raw").lower()
    if net not in SUPPORTED: raise ValueError("Unsupported transport")
    method = {"tcp":"raw", "ws":"websocket", "splithttp":"xhttp"}.get(net, net)
    security = first(p, "security", default="none").lower()
    if security not in ("none", "tls", "reality"): raise ValueError("Unsupported security")
    if security == "reality" and method not in ("raw", "xhttp", "grpc"):
        raise ValueError("REALITY cannot be combined with this transport")
    stream = {"network": method, "security": security}
    if method == "raw":
        raw = {}
        if first(p, "headerType", default="none").lower() == "http":
            raw["header"] = {"type":"http", "request":{"path":[first(p,"path",default="/")],"headers":{"Host":[first(p,"host",default=host)]}}}
        stream["rawSettings"] = raw
    elif method == "websocket":
        ws = {"path":first(p,"path",default="/"),"headers":{}}
        if first(p,"host"): ws["headers"]["Host"] = first(p,"host")
        stream["wsSettings"] = ws
    elif method == "grpc":
        grpc = {"serviceName":first(p,"serviceName","service_name"),"multiMode":first(p,"mode",default="gun").lower()=="multi"}
        if first(p,"authority"): grpc["authority"] = first(p,"authority")
        stream["grpcSettings"] = grpc
    elif method == "xhttp":
        xhttp = {"path":first(p,"path",default="/"),"mode":first(p,"mode",default="auto")}
        if first(p,"host"): xhttp["host"] = first(p,"host")
        extra = first(p,"extra")
        if extra:
            try:
                parsed_extra = json.loads(extra)
                if isinstance(parsed_extra, dict): xhttp["extra"] = parsed_extra
            except json.JSONDecodeError: pass
        stream["xhttpSettings"] = xhttp
    elif method == "httpupgrade":
        stream["httpupgradeSettings"] = {"path":first(p,"path",default="/"),"host":first(p,"host",default=host)}
    if security == "tls":
        tls = {
            "serverName": first(p, "sni", "servername", default=host),
            "allowInsecure": first(p, "allowInsecure", "insecure", default="0").lower() in ("1", "true", "yes"),
        }
        if first(p,"alpn"): tls["alpn"] = [x for x in first(p,"alpn").split(",") if x]
        if first(p,"fp"): tls["fingerprint"] = first(p,"fp")
        stream["tlsSettings"] = tls
    elif security == "reality":
        pbk = first(p,"pbk","publicKey")
        if not pbk: raise ValueError("REALITY public key missing")
        stream["realitySettings"] = {"serverName":first(p,"sni","servername",default=host),"fingerprint":first(p,"fp",default="chrome"),"password":pbk,"shortId":first(p,"sid"),"spiderX":first(p,"spx",default="/")}
        if first(p,"pqv"): stream["realitySettings"]["mldsa65Verify"] = first(p,"pqv")
    if protocol == "vless":
        if not credential: raise ValueError("VLESS UUID missing")
        user = {"id":credential,"encryption":first(p,"encryption",default="none")}
        if first(p,"flow"): user["flow"] = first(p,"flow")
        outbound = {"protocol":"vless","settings":{"vnext":[{"address":host,"port":port,"users":[user]}]},"streamSettings":stream}
    else:
        if not credential: raise ValueError("Trojan password missing")
        if security == "none": raise ValueError("Trojan without TLS/REALITY rejected")
        outbound = {"protocol":"trojan","settings":{"servers":[{"address":host,"port":port,"password":credential}]},"streamSettings":stream}
    return {"log":{"loglevel":"warning"},"inbounds":[{"listen":SOCKS_HOST,"port":SOCKS_PORT,"protocol":"socks","settings":{"auth":"noauth","udp":False}}],"outbounds":[outbound,{"protocol":"freedom","tag":"direct"}]}

def wait_for_xray(proc):
    for _ in range(50):
        if proc.poll() is not None: return False
        try:
            with socket.create_connection((SOCKS_HOST,SOCKS_PORT),timeout=1) as s:
                s.settimeout(1); s.sendall(b"\x05\x01\x00")
                if s.recv(2) == b"\x05\x00": return True
        except OSError: time.sleep(.2)
    return False

def proxies():
    px = f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
    return {"http":px,"https":px}

def check_tunnel(px):
    r = requests.get(IP_CHECK_URL,proxies=px,timeout=(8,15)); r.raise_for_status()
    ip = r.text.strip()
    if not re.fullmatch(r"[0-9a-fA-F:.]+",ip): raise ValueError("Invalid proxy IP response")
    return ip

def latency(px):
    start=time.perf_counter(); r=requests.get(LATENCY_URL,proxies=px,timeout=(8,15),headers={"Cache-Control":"no-cache"})
    if r.status_code not in (200,204): raise ValueError("Latency endpoint rejected request")
    return (time.perf_counter()-start)*1000

def speed(px):
    start=time.perf_counter(); total=0
    with requests.get(SPEED_URL,proxies=px,timeout=(10,35),stream=True,headers={"Cache-Control":"no-cache"}) as r:
        r.raise_for_status()
        for chunk in r.iter_content(65536):
            if chunk:
                total += len(chunk)
                if total >= 5_000_000: break
    elapsed=time.perf_counter()-start
    if total < 4_000_000 or elapsed <= 0: raise ValueError("Incomplete speed test")
    return total*8/elapsed/1_000_000

@lru_cache(maxsize=512)
def country_code(host):
    try:
        r=requests.get(f"https://ipwho.is/{host}",timeout=5,headers={"User-Agent":"JetConfigTester/2.0"})
        d=r.json()
        if d.get("success"): return (d.get("country_code") or "").upper()
    except (requests.RequestException,ValueError): pass
    return ""

def renamed_uri(uri, exit_ip, source_tag):
    # Country is based on the real public IP seen through the proxy tunnel,
    # not the config server's hostname.
    u=urlsplit(uri); cc=country_code(exit_ip)
    label=f"{FLAGS.get(cc,'🌐')} {NAMES.get(cc,'Unknown')} | {CHANNEL_LABEL} #{source_tag}"
    return urlunsplit((u.scheme,u.netloc,u.path,u.query,quote(label,safe="")))

def test_config(uri, source_tag):
    proc=None; log=tempfile.TemporaryFile(); phase="parse"
    try:
        cfg=parse_config(uri)
        with open("temp_config.json","w",encoding="utf-8") as f:
            json.dump(cfg,f,ensure_ascii=False)

        phase = "config_validation"
        validation = subprocess.run(
            [XRAY, "run", "-test", "-c", "temp_config.json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if validation.returncode != 0:
            details = (validation.stderr or validation.stdout or "").splitlines()
            safe_detail = details[-1][:180] if details else "Xray config validation failed"
            raise RuntimeError(safe_detail)

        phase="xray_start"
        proc=subprocess.Popen([XRAY,"run","-c","temp_config.json"],stdout=subprocess.DEVNULL,stderr=log)
        if not wait_for_xray(proc):
            log.seek(0)
            detail = log.read().decode("utf-8", errors="replace").splitlines()
            safe_detail = " | ".join(line[:160] for line in detail[-3:])
            raise RuntimeError(safe_detail or "Xray did not start")
        px=proxies(); phase="tunnel_check"; exit_ip=check_tunnel(px)
        phase="latency"; ms=latency(px)
        if ms > MAX_LATENCY_MS: return None
        phase="speed"; mbps=speed(px)
        if mbps < MIN_SPEED_MBPS: return None
        return {"config":renamed_uri(uri, exit_ip, source_tag),"latency_ms":round(ms,2),"speed_mbps":round(mbps,2)}
    except Exception as e:
        # Never log the full URI or credentials.
        print(f"Test failed during {phase}: {type(e).__name__}: {str(e)[:150]}")
        return None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=4)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)
        log.close()
        try: os.remove("temp_config.json")
        except OSError: pass

def main():
    print(f"Jet Config Tester | target Xray {XRAY_VERSION}")
    source_configs = []
    for source in SOURCES:
        items = []
        try:
            response = requests.get(
                source["url"], timeout=35,
                headers={"User-Agent": "JetConfigTester/2.0"}
            )
            response.raise_for_status()
            items = [
                line.strip() for line in response.text.splitlines()
                if line.strip().startswith(("vless://", "trojan://"))
            ]
            print(f"Source {source['name']}: {len(items)} candidate configs")
        except requests.RequestException as exc:
            print(f"Source {source['name']} download failed: {type(exc).__name__}")
        source_configs.append((source["name"], list(dict.fromkeys(items))))

    # Interleave sources so a large feed cannot crowd out the others.
    configs = []
    seen = set()
    max_depth = max((len(items) for _, items in source_configs), default=0)
    for index in range(max_depth):
        for source_name, items in source_configs:
            if index < len(items):
                uri = items[index]
                if uri not in seen:
                    seen.add(uri)
                    source_tags = {
                        "mehrtat-vless-collector": "ME",
                        "morpheusadam-v2ray-config": "MA",
                        "Idolvpn-Automate-V2ray-Config-Collector": "ID",
                        "Bllare-V2ray-Configs": "BL",
                        "Farid-Karimi-Config-Collector": "FK",
                        "miladtahanian-Config-Collector": "MT",
                    }
                    source_tag = source_tags.get(source_name, source_name[:2].upper())
                    configs.append((uri, source_tag))
                if len(configs) >= MAX_CONFIGS_PER_RUN:
                    break
        if len(configs) >= MAX_CONFIGS_PER_RUN:
            break

    print(f"Unique configurations selected for testing: {len(configs)} (limit {MAX_CONFIGS_PER_RUN})")
    passed = []
    for i, (uri, source_tag) in enumerate(configs, 1):
        result = test_config(uri, source_tag)
        if result:
            passed.append(result)
            print(f"{i}/{len(configs)} PASS | {result['latency_ms']} ms | {result['speed_mbps']} Mbps")
        else:
            print(f"{i}/{len(configs)} FAIL")

    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(passed, f, ensure_ascii=False, indent=2)
    print(f"Total tested: {len(configs)} | Passed: {len(passed)} | Failed: {len(configs)-len(passed)}")
    print("Failure phases are reported per config: parse, config_validation, xray_start, tunnel_check, latency, speed.")

if __name__ == "__main__": main()
