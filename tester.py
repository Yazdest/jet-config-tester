import json, os, re, socket, subprocess, tempfile, time
from functools import lru_cache
from urllib.parse import quote, unquote, urlsplit, urlunsplit, parse_qs
import requests

SOURCES = [
    {"name": "mehrtat-vless-collector", "tag": "ME", "urls": [
        "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt"]},
    {"name": "Bllare-V2ray-Configs", "tag": "BL", "urls": [
        "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/ALL.txt"]},
    {"name": "MahanKenway-Freedom-V2Ray", "tag": "MK", "urls": [
        "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt"]},
    {"name": "Delta-Kronecker-V2ray-Config", "tag": "DK", "urls": [
        "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/vless.txt"]},
    {"name": "barry-far-V2ray-Config", "tag": "BF", "urls": [
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt"]},
    {"name": "MatinGhanbari-v2ray-configs", "tag": "MG", "urls": [
        f"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub{i}.txt"
        for i in range(1, 40)]},
    {"name": "liketolivefree-kobabi", "tag": "KB", "urls": [
        "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub.txt"]},
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

def parse_config(uri):
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
                headers={"User-Agent":"JetConfigTester/3.0"})
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

def main():
    print(f"Jet Config Tester | target Xray {XRAY_VERSION}")
    source_configs = []
    for source in SOURCES:
        items = fetch_source(source)
        source_configs.append((source["name"], source["tag"], items))
        print(f"Source total {source['name']}: {len(items)} unique candidates")

    # Round-robin across sources to prevent a large subscription crowding out others.
    configs, seen = [], set()
    max_depth = max((len(items) for _, _, items in source_configs), default=0)
    for index in range(max_depth):
        for source_name, source_tag, items in source_configs:
            if index < len(items):
                uri = items[index]
                if uri not in seen:
                    seen.add(uri); configs.append((uri, source_tag))
                if len(configs) >= MAX_CONFIGS_PER_RUN: break
        if len(configs) >= MAX_CONFIGS_PER_RUN: break

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
    print("Supported tested protocols: VLESS, VMess, Trojan, Shadowsocks. SSR/TUIC/Hysteria2 and unsupported transports are skipped.")

if __name__ == "__main__": main()
