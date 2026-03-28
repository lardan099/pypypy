import requests
import re
import json
import subprocess
import time
import socket
import os
import base64
import threading
import queue
from urllib.parse import urlparse, parse_qs, unquote, quote
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Настройки ===
SING_BOX_PATH = "./sing-box"
TEST_URL = "http://cp.cloudflare.com/generate_204"
TIMEOUT = 8
THREADS = 5
STARTUP_WAIT = 1.5

VALID_SCHEMES = {"vless", "ss", "vmess", "trojan", "hy2", "hysteria2"}

WHITE_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
]

BLACK_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
]


# === Извлечение конфигов из источников ===

def config_key(url):
    """Ключ дедупликации — URL без фрагмента"""
    idx = url.find("#")
    return url[:idx] if idx != -1 else url


def fetch_configs(source_urls):
    """Скачивает и извлекает конфиг-ссылки из списка URL источников"""
    configs = {}  # key -> full url
    for src in source_urls:
        try:
            r = requests.get(src, timeout=15)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                scheme = line.split("://")[0] if "://" in line else ""
                if scheme in VALID_SCHEMES:
                    key = config_key(line)
                    if key not in configs:
                        configs[key] = line
        except Exception as e:
            print(f"[WARN] Не удалось скачать {src}: {e}")
    return configs


# === Парсеры протоколов ===

def parse_vless(url):
    """Парсит vless:// URL в sing-box outbound"""
    parsed = urlparse(url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    outbound = {
        "tag": "proxy",
        "type": "vless",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": parsed.username,
        "packet_encoding": params.get("packetEncoding", "xudp"),
    }

    flow = params.get("flow")
    if flow:
        outbound["flow"] = flow

    security = params.get("security", "")
    if security == "reality":
        outbound["tls"] = {
            "enabled": True,
            "server_name": params.get("sni", ""),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {
                "enabled": True,
                "public_key": params.get("pbk", ""),
                "short_id": params.get("sid", ""),
            },
        }
    elif security == "tls":
        tls = {"enabled": True, "server_name": params.get("sni", "")}
        fp = params.get("fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        alpn = params.get("alpn")
        if alpn:
            tls["alpn"] = alpn.split(",")
        outbound["tls"] = tls

    transport_type = params.get("type", "tcp")
    if transport_type == "ws":
        outbound["transport"] = {"type": "ws", "path": params.get("path", "/"), "headers": {"Host": params.get("host", "")}}
    elif transport_type == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", "")}
    elif transport_type == "xhttp" or transport_type == "splithttp":
        outbound["transport"] = {"type": "httpupgrade", "path": params.get("path", "/")}
    elif transport_type == "h2":
        outbound["transport"] = {"type": "http", "host": [params.get("host", "")], "path": params.get("path", "/")}

    return outbound


def parse_shadowsocks(url):
    """Парсит ss:// URL (SIP002) в sing-box outbound"""
    # ss://BASE64(method:password)@host:port#name
    # или ss://BASE64(method:password@host:port)#name (старый формат)
    raw = url[5:]  # убираем "ss://"
    fragment = ""
    if "#" in raw:
        raw, fragment = raw.rsplit("#", 1)

    if "@" in raw:
        # SIP002: userinfo@host:port
        userinfo, hostport = raw.rsplit("@", 1)
        # userinfo может быть base64 или method:password
        try:
            decoded = base64.urlsafe_b64decode(userinfo + "==").decode("utf-8")
        except Exception:
            decoded = unquote(userinfo)

        if ":" in decoded:
            method, password = decoded.split(":", 1)
        else:
            return None

        # Парсим host:port
        if hostport.startswith("["):
            # IPv6
            bracket_end = hostport.index("]")
            host = hostport[1:bracket_end]
            port = int(hostport[bracket_end + 2:])
        else:
            parts = hostport.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1])
    else:
        # Старый формат: всё в base64
        try:
            decoded = base64.urlsafe_b64decode(raw + "==").decode("utf-8")
        except Exception:
            return None
        # method:password@host:port
        if "@" not in decoded:
            return None
        userpart, hostport = decoded.rsplit("@", 1)
        method, password = userpart.split(":", 1)
        parts = hostport.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1])

    return {
        "tag": "proxy",
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


def parse_vmess(url):
    """Парсит vmess:// URL (base64 JSON) в sing-box outbound"""
    raw = url[8:]  # убираем "vmess://"
    try:
        decoded = base64.urlsafe_b64decode(raw + "==").decode("utf-8")
        config = json.loads(decoded)
    except Exception:
        try:
            decoded = base64.b64decode(raw + "==").decode("utf-8")
            config = json.loads(decoded)
        except Exception:
            return None

    outbound = {
        "tag": "proxy",
        "type": "vmess",
        "server": str(config.get("add", "")),
        "server_port": int(config.get("port", 443)),
        "uuid": str(config.get("id", "")),
        "alter_id": int(config.get("aid", 0)),
        "security": config.get("scy", config.get("security", "auto")),
    }

    # TLS
    if config.get("tls") == "tls":
        tls = {"enabled": True, "server_name": config.get("sni", config.get("host", ""))}
        fp = config.get("fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        alpn = config.get("alpn")
        if alpn:
            tls["alpn"] = alpn.split(",") if isinstance(alpn, str) else alpn
        outbound["tls"] = tls

    # Transport
    net = config.get("net", "tcp")
    if net == "ws":
        transport = {"type": "ws", "path": config.get("path", "/")}
        host = config.get("host", "")
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": config.get("path", "")}
    elif net == "h2":
        outbound["transport"] = {
            "type": "http",
            "host": [config.get("host", "")],
            "path": config.get("path", "/"),
        }

    return outbound


def parse_trojan(url):
    """Парсит trojan:// URL в sing-box outbound"""
    parsed = urlparse(url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    outbound = {
        "tag": "proxy",
        "type": "trojan",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or ""),
    }

    # Trojan всегда с TLS
    sni = params.get("sni", parsed.hostname)
    tls = {"enabled": True, "server_name": sni}
    fp = params.get("fp")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    alpn = params.get("alpn")
    if alpn:
        tls["alpn"] = alpn.split(",")
    if params.get("allowInsecure") == "1":
        tls["insecure"] = True
    outbound["tls"] = tls

    # Transport
    transport_type = params.get("type", "tcp")
    if transport_type == "ws":
        outbound["transport"] = {"type": "ws", "path": params.get("path", "/"), "headers": {"Host": params.get("host", "")}}
    elif transport_type == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", "")}

    return outbound


def parse_hysteria2(url):
    """Парсит hy2:// или hysteria2:// URL в sing-box outbound"""
    parsed = urlparse(url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    outbound = {
        "tag": "proxy",
        "type": "hysteria2",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or ""),
    }

    sni = params.get("sni", parsed.hostname)
    outbound["tls"] = {"enabled": True, "server_name": sni, "insecure": True}

    return outbound


def parse_config(url):
    """Диспатчер: выбирает парсер по схеме URL"""
    try:
        scheme = url.split("://")[0].lower()
        if scheme == "vless":
            return parse_vless(url)
        elif scheme == "ss":
            return parse_shadowsocks(url)
        elif scheme == "vmess":
            return parse_vmess(url)
        elif scheme == "trojan":
            return parse_trojan(url)
        elif scheme in ("hy2", "hysteria2"):
            return parse_hysteria2(url)
    except Exception:
        pass
    return None


# === Валидация через sing-box ===

def create_singbox_config(outbound, listen_port):
    return {
        "log": {"level": "silent"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": listen_port,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
    }


# Пул свободных портов
port_pool = queue.Queue()
for p in range(20001, 20001 + THREADS):
    port_pool.put(p)


def check_config(url):
    """Проверяет один конфиг через sing-box. Возвращает (url, success, latency_ms)"""
    outbound = parse_config(url)
    if not outbound:
        return url, False, 0

    port = port_pool.get()
    config = create_singbox_config(outbound, port)
    config_file = f"tmp_{port}.json"
    proc = None

    try:
        with open(config_file, "w") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            [SING_BOX_PATH, "run", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(STARTUP_WAIT)

        start = time.time()
        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        r = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        if r.status_code in (200, 204):
            latency = int((time.time() - start) * 1000)
            return url, True, latency
    except Exception:
        pass
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        try:
            os.remove(config_file)
        except Exception:
            pass
        port_pool.put(port)

    return url, False, 0


def validate_configs(configs):
    """Проверяет список конфигов параллельно. Возвращает set валидных URL."""
    valid = set()
    total = len(configs)
    done = 0

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(check_config, url): url for url in configs}
        for future in as_completed(futures):
            url, success, latency = future.result()
            done += 1
            if success:
                print(f"[{done}/{total}] [OK] {latency}ms | {url[:80]}...")
                valid.add(url)
            else:
                print(f"[{done}/{total}] [DEAD] | {url[:80]}...")

    return valid


# === Запись результатов ===

def write_output(filename, title, configs):
    """Записывает файл с заголовком и конфигами"""
    moscow_tz = timezone(timedelta(hours=3))
    now = datetime.now(moscow_tz)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M")

    lines = [
        f"# profile-title: {title}",
        "# profile-update-interval: 5",
        f"# Date/Time: {date_str} / {time_str} (Moscow)",
        f"# Количество: {len(configs)}",
        "",
    ]
    lines.extend(sorted(configs))

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# === Main ===

def main():
    print("=== Сбор конфигов из источников ===")
    white_raw = fetch_configs(WHITE_SOURCES)
    black_raw = fetch_configs(BLACK_SOURCES)
    print(f"Белые списки: {len(white_raw)} уникальных конфигов")
    print(f"Обычные конфиги: {len(black_raw)} уникальных конфигов")

    # Объединяем для валидации (не проверяем дважды)
    all_keys = set(white_raw.keys()) | set(black_raw.keys())
    all_configs = {}
    for k in all_keys:
        all_configs[k] = white_raw.get(k) or black_raw.get(k)

    print(f"\nВсего уникальных для проверки: {len(all_configs)}")
    print(f"=== Проверка конфигов ({THREADS} потоков) ===\n")

    valid_urls = validate_configs(list(all_configs.values()))
    valid_keys = {config_key(url) for url in valid_urls}

    # Разделяем обратно
    white_valid = [white_raw[k] for k in white_raw if k in valid_keys]
    black_valid = [black_raw[k] for k in black_raw if k in valid_keys]

    print(f"\n=== Результаты ===")
    print(f"Белые списки: {len(white_valid)} валидных")
    print(f"Обычные конфиги: {len(black_valid)} валидных")

    write_output("white_configs.txt", "БЕЛЫЕ СПИСКИ", white_valid)
    write_output("configs.txt", "ОБЫЧНЫЕ КОНФИГИ", black_valid)

    print("Файлы записаны: white_configs.txt, configs.txt")


if __name__ == "__main__":
    main()
