import json
import time
import socket
import subprocess
import requests
import os

from urllib.parse import urlparse, parse_qs


# ==============================
# Main settings
# ==============================

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

SUPPORTED_NETWORKS = {
    "raw",
    "tcp",
    "ws",
    "websocket",
    "grpc",
    "xhttp",
    "splithttp",
    "httpupgrade"
}


# ==============================
# Helper functions
# ==============================

def first(params, *keys, default=""):
    for key in keys:
        values = params.get(key)
        if values:
            return values[0]
    return default


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


# ==============================
# Parse VLESS / Trojan
# ==============================

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

    network = first(
        params,
        "type",
        "network",
        default="raw"
    ).lower()

    security = first(
        params,
        "security",
        default="none"
    ).lower()

    if network not in SUPPORTED_NETWORKS:
        raise ValueError("Unsupported network: " + network)

    if security not in ("tls", "reality", "none"):
        raise ValueError("Unsupported security: " + security)

    stream = {
        "network": network,
        "security": security
    }

    # --------------------------
    # RAW / TCP
    # --------------------------

    if network in ("raw", "tcp"):

        header_type = first(params, "headerType", default="none")

        if header_type == "http":
            stream["rawSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [first(params, "path", default="/")],
                        "headers": {
                            "Host": [
                                first(params, "host", default=host)
                            ]
                        }
                    }
                }
            }

    # --------------------------
    # WebSocket
    # --------------------------

    elif network in ("ws", "websocket"):

        stream["wsSettings"] = {
            "path": first(params, "path", default="/"),
            "headers": {
                "Host": first(params, "host", default=host)
            }
        }

    # --------------------------
    # gRPC
    # --------------------------

    elif network == "grpc":

        stream["grpcSettings"] = {
            "serviceName": first(
                params,
                "serviceName",
                "service_name",
                default=""
            ),
            "multiMode": first(
                params,
                "mode",
                default="gun"
            ) == "multi"
        }

    # --------------------------
    # XHTTP
    # --------------------------

    elif network in ("xhttp", "splithttp"):

        stream["xhttpSettings"] = {
            "path": first(params, "path", default="/"),
            "host": first(params, "host", default=""),
            "mode": first(params, "mode", default="auto")
        }

    # --------------------------
    # HTTP Upgrade
    # --------------------------

    elif network == "httpupgrade":

        stream["httpupgradeSettings"] = {
            "path": first(params, "path", default="/"),
            "host": first(params, "host", default=host)
        }

    # ==========================
    # TLS settings
    # ==========================

    if security == "tls":

        tls_settings = {
            "serverName": first(params, "sni", "servername", default=host)
        }

        alpn = first(params, "alpn")

        if alpn:
            tls_settings["alpn"] = alpn.split(",")

        fingerprint = first(params, "fp")

        if fingerprint:
            tls_settings["fingerprint"] = fingerprint

        stream["tlsSettings"] = tls_settings

    # ==========================
    # REALITY settings
    # ==========================

    elif security == "reality":

        public_key = first(params, "pbk", "publicKey")

        if not public_key:
            raise ValueError("Reality public key is missing")

        if network not in ("raw", "tcp", "xhttp", "splithttp", "grpc"):
            raise ValueError(
                "REALITY does not support this network: " + network
            )

        stream["realitySettings"] = {
            "serverName": first(
                params,
                "sni",
                "servername",
                default=host
            ),
            "fingerprint": first(params, "fp", default="chrome"),
            "password": public_key,
            "shortId": first(params, "sid"),
            "spiderX": first(params, "spx", default="/")
        }

    # ==========================
    # VLESS outbound
    # ==========================

    if protocol == "vless":

        if not username:
            raise ValueError("VLESS UUID is missing")

        user = {
            "id": username,
            "encryption": first(params, "encryption", default="none"),
            "level": 0
        }

        flow = first(params, "flow")

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

    # ==========================
    # Trojan outbound
    # ==========================

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

    # ==========================
    # Complete Xray config
    # ==========================

    return {
        "log": {
            "loglevel": "warning"
        },
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


# ==============================
# Wait for Xray
# ==============================

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


# ==============================
# Latency test
# ==============================

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
        raise ValueError("Latency test returned HTTP " + str(response.status_code))

    return elapsed


# ==============================
# Speed test
# ==============================

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


# ==============================
# Test one configuration
# ==============================

def test_config(uri):

    process = None
    phase = "parse"

    try:

        config = parse_config(uri)

        with open("temp_config.json", "w", encoding="utf-8") as file:
            json.dump(config, file, ensure_ascii=False)

        phase = "xray_start"

        process = subprocess.Popen(
            [XRAY, "run", "-c", "temp_config.json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_for_xray(process):
            raise RuntimeError("Xray proxy did not start")

        proxies = {
            "http": f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}",
            "https": f"socks5h://{SOCKS_HOST}:{SOCKS_PORT}"
        }

        phase = "latency"

        latency = measure_latency(proxies)

        if latency > MAX_LATENCY_MS:
            return None

        phase = "speed"

        speed = measure_speed(proxies)

        if speed < MIN_SPEED_MBPS:
            return None

        return {
            "config": uri,
            "latency_ms": round(latency, 2),
            "speed_mbps": round(speed, 2)
        }

    except Exception as error:

        # Never print the full config URI or its credentials.
        print(
            f"Test failed during {phase}: "
            f"{type(error).__name__}: {str(error)[:200]}"
        )

        return None

    finally:

        if process:

            process.terminate()

            try:
                process.wait(timeout=3)

            except subprocess.TimeoutExpired:
                process.kill()


# ==============================
# Main
# ==============================

def main():

    print("Downloading configurations...")

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
    print("--------------------------------")


if __name__ == "__main__":
    main()
