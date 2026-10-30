import json
import time
import socket
import subprocess
import requests
from urllib.parse import urlparse, parse_qs

SOURCE_URL = "https://sub.vlessfo.ru/vlessforu/working_configs.txt"

XRAY = "./bin/xray"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 10808

MIN_SPEED_MBPS = 5.0
MAX_LATENCY_MS = 300.0

LATENCY_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=5000000"

LATENCY_TIMEOUT = 15
SPEED_TIMEOUT = 30
RESULT_FILE = "passed_configs.json"

SUPPORTED_NETWORKS = {"tcp", "ws", "grpc"}


def first(params, key, default=""):
    values = params.get(key)
    return values[0] if values else default


def download_configs():
    response = requests.get(
        SOURCE_URL,
        timeout=30,
        headers={"User-Agent": "JetConfigTester/1.0"}
    )
    response.raise_for_status()

    configs = []

    for line in response.text.splitlines():
        line = line.strip()

        if line.startswith(("vless://", "trojan://")):
            configs.append(line)

    return list(dict.fromkeys(configs))


def parse_config(uri):
    parsed = urlparse(uri)
    params = parse_qs(parsed.query, keep_blank_values=True)

    protocol = parsed.scheme.lower()

    if protocol not in ("vless", "trojan"):
        raise ValueError("Unsupported protocol")

    if not parsed.hostname or not parsed.port:
        raise ValueError("Missing server address or port")

    host = parsed.hostname
    port = parsed.port
    username = parsed.username or ""

    network = first(params, "type", "tcp").lower()
    security = first(params, "security", "none").lower()

    if network not in SUPPORTED_NETWORKS:
        raise ValueError("Unsupported network: " + network)

    if security not in ("tls", "reality", "none"):
        raise ValueError("Unsupported security: " + security)

    stream = {
        "network": network,
        "security": security
    }

    if network == "ws":
        ws_settings = {
            "path": first(params, "path", "/"),
            "headers": {
                "Host": first(params, "host", host)
            }
        }

        stream["wsSettings"] = ws_settings

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": first(params, "serviceName", ""),
            "multiMode": first(params, "mode", "gun") == "multi"
        }

    elif network == "tcp":
        header_type = first(params, "headerType", "none")

        if header_type == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [first(params, "path", "/")],
                        "headers": {
                            "Host": [first(params, "host", host)]
                        }
                    }
                }
            }

    if security == "tls":
        tls_settings = {
            "serverName": first(params, "sni", host),
            "allowInsecure": first(params, "allowInsecure", "0") == "1"
        }

        alpn = first(params, "alpn", "")
        if alpn:
            tls_settings["alpn"] = alpn.split(",")

        fingerprint = first(params, "fp", "")
        if fingerprint:
            tls_settings["fingerprint"] = fingerprint

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        public_key = first(params, "pbk", "")
        if not public_key:
            raise ValueError("Reality public key is missing")

        stream["realitySettings"] = {
            "serverName": first(params, "sni", host),
            "fingerprint": first(params, "fp", "chrome"),
            "publicKey": public_key,
            "shortId": first(params, "sid", ""),
            "spiderX": first(params, "spx", "/")
        }

    if protocol == "vless":
        user = {
            "id": username,
            "encryption": first(params, "encryption", "none"),
            "level": 0
        }

        flow = first(params, "flow", "")
        if flow:
            user["flow"] = flow

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [user]
                }]
            },
            "streamSettings": stream
        }

    else:
        if not username:
            raise ValueError("Trojan password is missing")

        if security == "none":
            raise ValueError("Trojan without TLS is not supported")

        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": username
                }]
            },
            "streamSettings": stream
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": SOCKS_HOST,
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False
            }
        }],
        "outbounds": [
            outbound,
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }


def wait_for_xray(process):
    for _ in range(40):
        if process.poll() is not None:
            return False

        try:
            with socket.create_connection(
                (SOCKS_HOST, SOCKS_PORT),
                timeout=1
            ):
                return True
        except OSError:
            time.sleep(0.25)

    return False


def measure_latency(proxies):
    start = time.perf_counter()

    response = requests.get(
        LATENCY_URL,
        proxies=proxies,
        timeout=LATENCY_TIMEOUT,
        headers={"Cache-Control": "no-cache"}
    )

    elapsed = (time.perf_counter() - start) * 1000

    if response.status_code not in (200, 204):
        raise ValueError("Latency test failed")

    return elapsed


def measure_speed(proxies):
    start = time.perf_counter()
    downloaded = 0

    with requests.get(
        SPEED_URL,
        proxies=proxies,
        timeout=SPEED_TIMEOUT,
        stream=True,
        headers={"Cache-Control": "no-cache"}
    ) as response:

        response.raise_for_status()

        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                downloaded += len(chunk)

    elapsed = time.perf_counter() - start

    if elapsed <= 0 or downloaded < 1000000:
        raise ValueError("Speed test did not download enough data")

    return (downloaded * 8) / elapsed / 1000000


def test_config(uri):
    process = None

    try:
        config = parse_config(uri)

        with open("temp_config.json", "w", encoding="utf-8") as file:
            json.dump(config, file, ensure_ascii=False)

        process = subprocess.Popen(
            [XRAY, "run", "-c", "temp_config.json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_for_xray(process):
            raise ValueError("Xray proxy did not start")

        proxies = {
            "http": f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}",
            "https": f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
        }

        latency = measure_latency(proxies)

        if latency > MAX_LATENCY_MS:
            return None

        speed = measure_speed(proxies)

        if speed < MIN_SPEED_MBPS:
            return None

        return {
            "config": uri,
            "latency_ms": round(latency, 2),
            "speed_mbps": round(speed, 2)
        }

    except Exception as error:
        # Do not print the URI or credentials into public workflow logs.
        print("Test failed:", type(error).__name__)
        return None

    finally:
        if process:
            process.terminate()

            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def main():
    configs = download_configs()

    print("Unique configurations received:", len(configs))

    passed = []

    for index, config in enumerate(configs, 1):
        result = test_config(config)

        if result:
            passed.append(result)

            print(
                f"{index}/{len(configs)} PASS | "
                f"Latency: {result['latency_ms']} ms | "
                f"Speed: {result['speed_mbps']} Mbps"
            )
        else:
            print(f"{index}/{len(configs)} FAIL")

    with open(RESULT_FILE, "w", encoding="utf-8") as file:
        json.dump(
            passed,
            file,
            ensure_ascii=False,
            indent=2
        )

    print("--------------------------------")
    print("Total configurations:", len(configs))
    print("Passed configurations:", len(passed))
    print("Failed configurations:", len(configs) - len(passed))


if __name__ == "__main__":
    main()
