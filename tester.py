import json
import time
import socket
import subprocess
import requests
from urllib.parse import urlparse, parse_qs, unquote

SOURCE_URL = "https://sub.vlessfo.ru/vlessforu/working_configs.txt"

XRAY = "./bin/xray"
SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 10808

MIN_SPEED_MBPS = 5
MAX_LATENCY_MS = 300

TEST_URL = "https://speed.cloudflare.com/__down?bytes=5000000"
LATENCY_URL = "https://www.gstatic.com/generate_204"

TIMEOUT = 15
RESULT_FILE = "passed_configs.json"


def download_configs():
    response = requests.get(SOURCE_URL, timeout=30)
    response.raise_for_status()

    configs = []

    for line in response.text.splitlines():
        line = line.strip()

        if line.startswith(("vless://", "trojan://")):
            configs.append(line)

    return list(dict.fromkeys(configs))


def parse_config(uri):
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    protocol = parsed.scheme.lower()

    if protocol not in ("vless", "trojan"):
        raise ValueError("Unsupported protocol")

    if not parsed.hostname or not parsed.port:
        raise ValueError("Invalid server address")

    host = parsed.hostname
    port = parsed.port
    network = params.get("type", ["tcp"])[0]
    security = params.get("security", ["none"])[0]

    stream = {
        "network": network,
        "security": security
    }

    if network == "ws":
        stream["wsSettings"] = {
            "path": unquote(params.get("path", ["/"])[0]),
            "headers": {
                "Host": params.get("host", [host])[0]
            }
        }

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0]
        }

    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": params.get("sni", [host])[0],
            "alpn": params.get("alpn", ["h2,http/1.1"])[0].split(","),
            "allowInsecure": False
        }

    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": params.get("sni", [host])[0],
            "fingerprint": params.get("fp", ["chrome"])[0],
            "publicKey": params.get("pbk", [""])[0],
            "shortId": params.get("sid", [""])[0],
            "spiderX": params.get("spx", ["/"])[0]
        }

    user = unquote(parsed.username or "")

    if protocol == "vless":
        user_config = {
            "id": user,
            "encryption": params.get("encryption", ["none"])[0]
        }

        flow = params.get("flow", [""])[0]
        if flow:
            user_config["flow"] = flow

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        **user_config,
                        "level": 0
                    }]
                }]
            },
            "streamSettings": stream
        }

    else:
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": user
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
            "settings": {"udp": True}
        }],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"}
        ]
    }


def wait_for_proxy():
    for _ in range(30):
        try:
            with socket.create_connection(
                (SOCKS_HOST, SOCKS_PORT), timeout=1
            ):
                return True
        except OSError:
            time.sleep(0.5)

    return False


def test_config(uri):
    process = None

    try:
        config = parse_config(uri)

        with open("temp_config.json", "w") as file:
            json.dump(config, file)

        process = subprocess.Popen(
            [XRAY, "run", "-c", "temp_config.json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_for_proxy():
            return None

        proxies = {
            "http": f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}",
            "https": f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
        }

        start = time.perf_counter()

        response = requests.get(
            LATENCY_URL,
            proxies=proxies,
            timeout=TIMEOUT
        )

        latency = (time.perf_counter() - start) * 1000

        if response.status_code not in (200, 204):
            return None

        if latency > MAX_LATENCY_MS:
            return None

        start = time.perf_counter()

        response = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=30,
            stream=True
        )

        response.raise_for_status()

        downloaded = 0

        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                downloaded += len(chunk)

        elapsed = time.perf_counter() - start

        if elapsed <= 0 or downloaded == 0:
            return None

        speed_mbps = (downloaded * 8) / elapsed / 1_000_000

        if speed_mbps < MIN_SPEED_MBPS:
            return None

        return {
            "config": uri,
            "latency_ms": round(latency, 2),
            "speed_mbps": round(speed_mbps, 2)
        }

    except Exception:
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

    print(f"Downloaded {len(configs)} unique configs")

    passed = []

    for index, config in enumerate(configs, 1):
        result = test_config(config)

        if result:
            passed.append(result)
            print(
                f"Config {index}: PASS | "
                f"{result['latency_ms']} ms | "
                f"{result['speed_mbps']} Mbps"
            )
        else:
            print(f"Config {index}: FAIL")

    with open(RESULT_FILE, "w") as file:
        json.dump(passed, file, ensure_ascii=False, indent=2)

    print(f"Passed configs: {len(passed)}")


if __name__ == "__main__":
    main()
