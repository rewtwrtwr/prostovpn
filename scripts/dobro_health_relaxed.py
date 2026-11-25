#!/usr/bin/env python3
# ============================================================================
# dobro_health_relaxed.py — "расслабленная" версия health-check подписки ДоброВПН.
#
# Отличие от строгой версии (dobro_health.py):
#   - НЕ требует 100% аптайм. Берутся узлы с d30 >= 90% (MIN_UPTIME).
#     Это даёт ~96 кандидатов вместо 15 — большой пул для выбора лучших.
#   - ДВУХЭТАПНАЯ методика (по тактике Георгия, 25.11.2026):
#     ЭТАП 1 — ПИНГ/СТАБИЛЬНОСТЬ: каждый узел пингуется 5 раз с паузой
#     3 с между пробами (запросы к api.ipify.org через туннель). Считаются
#     медиана, джиттер (ст. отклонение) и максимум. Отбираются узлы с
#     минимальным джиттером и без скачков: джиттер <= MAX_JITTER и
#     максимум <= медиана * SPIKE_FACTOR. Нестабильные узлы до замера
#     скорости НЕ доходят.
#     ЭТАП 2 — СКОРОСТЬ (один раз, как Speedtest): для отобранных узлов
#     скорость меряется ОДИН раз мультипоточным тестом — 4 параллельных
#     потока скачивания по 10 МБ и 4 параллельных потока аплоада по 10 МБ.
#     Одиночный однопоточный замер 10 МБ ВРЁТ (доказано 25.11.2026:
#     Польша #10 на раннере показала 32/14 Мбит/с, а живой Speedtest
#     Георгия через тот же узел — 335/303 Мбит/с): короткий файл
#     заканчивается раньше, чем TCP выходит на полную скорость, и все
#     узлы сваливаются в один коридор 30–35 Мбит/с. Мультипоток, как
#     у Speedtest, меряет реальную пропускную способность.
#   - Ранжирование: сначала по скорости скачивания (больше — лучше),
#     потом по медиане пинга (меньше — лучше).
#   - Узлы со скоростью ниже MIN_SPEED (скачивание, 50 Мбит/с) или
#     MIN_UPLOAD (аплоад, 50 Мбит/с — тот же порог) в файл НЕ попадают.
#     RU-гарантия — исключение: RU-узлы проходят по живому тесту без
#     порога скорости, но обязаны пройти ЭТАП 1 (пинг/стабильность) и
#     замер скорости. Если по фильтру джиттера проходит меньше RU_TARGET
#     RU-узлов — добираются RU-узлы с наименьшим джиттером (до цели),
#     они помечаются в таблице.
#   - RU-гарантия сохранена: лучшие RU-узлы (Москва/Новосибирск) обязательно
#     тестируются, пока не наберётся RU_TARGET=3 прошедших.
#
# Что делает (как строгая версия):
#   1. Читает узлы из dobro.b64 (зеркало подписки в репозитории).
#   2. Качает https://status.azmov.site/data/status.json и берёт серверы
#      с d30 >= MIN_UPTIME. Игровые (group == 'games') и LTE исключаются.
#   3. Этап 1: каждый кандидат пингуется 5 раз (пауза 3 с) через xray-core.
#   4. Этап 2: отобранные узлы проходят мультипоточный замер скорости.
#   5. В dobro-relaxed.yaml и dobro-relaxed.txt пишутся ТОЛЬКО узлы,
#      прошедшие оба этапа (стабильный пинг + пороги скорости).
#   6. Пишет отчёт dobro-relaxed.md с таблицей результатов.
#
# Fail-closed: если живых узлов 0 — старые relaxed-файлы НЕ перезаписываются.
# Запуск: python3 dobro_health_relaxed.py [--xray /path/to/xray] [--out-dir .]
# Требует: xray-core (скачивается workflow), curl, python3.
# ============================================================================
import base64
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote

STATUS_URL = "https://status.azmov.site/data/status.json"
IPIFY_URL = "https://api.ipify.org"
# Скорость: каждый поток качает/льёт 10 МБ. Cloudflare __down на больших
# размерах отдаёт 403 после частых запросов, поэтому только 10 МБ на поток,
# а пропускная способность набирается количеством потоков (как у Speedtest).
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
SPEED_FALLBACK = "https://cachefly.cachefly.net/10mb.test"
# Аплоад: POST 10 МБ на Cloudflare __up (тот же эндпоинт, что у speed-теста).
UPLOAD_URL = "https://speed.cloudflare.com/__up"
UPLOAD_SIZE = 10_000_000  # 10 МБ аплоад-пробы на поток
UPLOAD_TIMEOUT = 60
IP_TIMEOUT = 20
SPEED_TIMEOUT = 60


def normalize(name):
    """'★ 🇩🇪 Германия #25' -> 'Германия #25'; '★ 🤖 Нейросети 🇫🇮 Финляндия' -> 'Финляндия'."""
    n = name.replace("★", "").replace("Нейросети", "")
    n = re.sub(r"[^\w\s#]", "", n, flags=re.UNICODE)
    n = re.sub(r"\s+", " ", n).strip()
    return n


def parse_vless(link):
    body, _, frag = link[8:].partition("#")
    name = unquote(frag) or "vless"
    userinfo_host, _, query = body.partition("?")
    if "@" not in userinfo_host:
        return None
    uuid, _, hostport = userinfo_host.partition("@")
    host, _, port = hostport.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return None
    q = parse_qs(query)
    g = lambda k, d="": q.get(k, [d])[0]
    return {
        "name": name, "type": "vless", "server": host, "port": port,
        "uuid": uuid, "sni": g("sni"), "fp": g("fp") or "firefox",
        "pbk": g("pbk"), "sid": g("sid"), "flow": g("flow") or "",
        "network": g("type", "tcp"), "link": link,
    }


def parse_ss(link):
    body, _, frag = link[5:].partition("#")
    name = unquote(frag) or "ss"
    body = body.split("?")[0]
    if "@" in body:
        pre, _, hostport = body.partition("@")
        try:
            userinfo = base64.urlsafe_b64decode(pre + "=" * (-len(pre) % 4)).decode("utf-8", "replace")
        except Exception:
            return None
    else:
        try:
            dec = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", "replace")
        except Exception:
            return None
        if "@" not in dec:
            return None
        userinfo, _, hostport = dec.rpartition("@")
    method, _, password = userinfo.partition(":")
    host, _, port = hostport.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return None
    if not method or not password or not host:
        return None
    return {
        "name": name, "type": "ss", "server": host, "port": port,
        "cipher": method, "password": password, "link": link,
    }


RU_TARGET = 3  # сколько RU-узлов гарантируем в relaxed-файле (если пройдут живой тест)
MIN_UPTIME = 90.0  # минимальный аптайм за 30 дней (d30), % — вместо 100% в строгой версии
MIN_SPEED = 50.0  # минимальная скорость СКАЧИВАНИЯ, Мбит/с — медленнее в файл не попадает (кроме RU-гарантии: RU-узлы проходят по живому тесту без порога скорости)
MIN_UPLOAD = 50.0  # минимальная скорость АПЛОАДА, Мбит/с — тот же порог, что и у скачивания (по просьбе Георгия 25.11.2026 «аплоад тоже 50+»).
# --- Этап 1: пинг/стабильность (тактика Георгия 25.11.2026) ---
PING_PROBES = 5  # сколько раз пингуем каждый узел на этапе 1
PING_GAP_SECONDS = 3  # пауза между пинг-пробами, с
MAX_JITTER = 100.0  # макс. джиттер (ст. отклонение 5 проб), мс — выше не берём
SPIKE_FACTOR = 2.0  # скачок: макс. пинг должен быть <= медиана * SPIKE_FACTOR
# --- Этап 2: скорость как у Speedtest (мультипоток) ---
SPEED_STREAMS = 4  # параллельных потоков скачивания и аплоада


def is_ru(name):
    """Российский сервер: Москва или Новосибирск (по имени на status-сайте)."""
    return ("Москва" in (name or "")) or ("Новосибирск" in (name or ""))


def fetch_status():
    """Весь status.json: {имя: {'group': ..., 'up': {'d30':..,'d7':..,'d1':..}}}."""
    req = urllib.request.Request(STATUS_URL, headers={"User-Agent": "dobro-health/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    out = {}
    for s in data.get("servers", []):
        out[s.get("name")] = {"group": s.get("group"),
                              "up": s.get("up") or {}}
    return out


def fetch_status_relaxed(status=None):
    """Множество имён серверов с d30 >= MIN_UPTIME, без games и LTE."""
    if status is None:
        status = fetch_status()
    return {name for name, s in status.items()
            if ((s["up"].get("d30") or 0) >= MIN_UPTIME and s["group"] != "games"
                and "lte" not in name.lower())}


def load_nodes(b64_path):
    raw = open(b64_path, encoding="utf-8").read().strip()
    dec = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
    nodes = []
    for line in dec.splitlines():
        line = line.strip()
        if not line:
            continue
        p = parse_vless(line) if line.startswith("vless://") \
            else parse_ss(line) if line.startswith("ss://") else None
        if p:
            nodes.append(p)
    return nodes


def xray_config(node, socks_port):
    """Конфиг xray: SOCKS-inbound -> один узел (vless REALITY / ss)."""
    if node["type"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node["server"], "port": node["port"],
                    "users": [{"id": node["uuid"], "flow": node["flow"],
                               "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network": node.get("network", "tcp"),
                "security": "reality",
                "realitySettings": {
                    "serverName": node["sni"],
                    "fingerprint": node.get("fp") or "firefox",
                    "publicKey": node["pbk"],
                    "shortId": node["sid"],
                },
            },
        }
    else:  # ss
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": node["server"], "port": node["port"],
                    "method": node["cipher"], "password": node["password"],
                }],
            },
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "protocol": "socks", "port": socks_port,
            "listen": "127.0.0.1",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def run_curl(args, timeout):
    try:
        r = subprocess.run(["curl", "-s", "--max-time", str(timeout)] + args,
                           capture_output=True, text=True, timeout=timeout + 10)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", -1


def start_xray(xray_bin, node, socks_port, tmpdir):
    """Поднять xray для узла, дождаться SOCKS-порта. Возвращает proc или None."""
    import socket
    cfg_path = os.path.join(tmpdir, "xray-%d.json" % socks_port)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(xray_config(node, socks_port), f)
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return None  # xray умер сразу — узел мёртв
        try:
            with socket.create_connection(("127.0.0.1", socks_port), timeout=1):
                time.sleep(2)  # дать xray завершить инициализацию
                return proc
        except OSError:
            time.sleep(0.5)
    return None


def stop_xray(proc):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def ping_pass(ts):
    """Этап 1 пройден? ts — список времён 5 проб (мс).
    Джиттер (ст. отклонение) <= MAX_JITTER и без скачков
    (максимум <= медиана * SPIKE_FACTOR)."""
    if len(ts) < PING_PROBES:
        return False
    med = statistics.median(ts)
    jit = statistics.pstdev(ts) if len(ts) > 1 else 0.0
    return jit <= MAX_JITTER and max(ts) <= med * SPIKE_FACTOR


def ping_stage(xray_bin, node, socks_port, tmpdir):
    """Этап 1: живой тест + пинг 5 раз с паузой 3 с.
    Возвращает dict с пинг-статистикой (или status DEAD/FLAKY)."""
    res = {"name": node["name"], "norm": normalize(node["name"]),
           "type": node["type"], "status": "DEAD", "exit_ip": "",
           "ping_med": None, "ping_jit": None, "ping_max": None,
           "ping_min": None, "ping_probes": []}
    proc = start_xray(xray_bin, node, socks_port, tmpdir)
    if proc is None:
        return res
    try:
        proxy = "socks5h://127.0.0.1:%d" % socks_port
        # Выходной IP (подтверждает, что туннель работает)
        out, rc = run_curl(["--socks5-hostname", proxy, IPIFY_URL], IP_TIMEOUT)
        if rc != 0 or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", out or ""):
            return res
        res["exit_ip"] = out
        # Пинг: 5 проб api.ipify.org с паузой 3 с между пробами
        ts = []
        for i in range(PING_PROBES):
            t0 = time.monotonic()
            _, rc = run_curl(["--socks5-hostname", proxy, IPIFY_URL], 15)
            dt = (time.monotonic() - t0) * 1000.0
            if rc == 0:
                ts.append(dt)
            if i < PING_PROBES - 1:
                time.sleep(PING_GAP_SECONDS)
        if not ts:
            res["status"] = "FLAKY"
            return res
        res["ping_probes"] = [round(t, 1) for t in ts]
        res["ping_med"] = round(statistics.median(ts), 1)
        res["ping_min"] = round(min(ts), 1)
        res["ping_max"] = round(max(ts), 1)
        res["ping_jit"] = round(statistics.pstdev(ts), 1) if len(ts) > 1 else 0.0
        res["status"] = "OK" if ping_pass(ts) else "UNSTABLE"
        return res
    finally:
        stop_xray(proc)


def _download_one(args):
    """Один поток скачивания: 10 МБ через прокси. Возвращает (байты, секунды)."""
    proxy, url = args
    t0 = time.monotonic()
    out, rc = run_curl(["--socks5-hostname", proxy, "-o", "/dev/null",
                        "-w", "%{size_download}", url], SPEED_TIMEOUT)
    dt = time.monotonic() - t0
    if rc == 0 and out.isdigit() and int(out) > 0:
        return int(out), dt
    return 0, dt


def _upload_one(args):
    """Один поток аплоада: POST 10 МБ через прокси. Возвращает (байты, секунды)."""
    proxy, upload_file = args
    t0 = time.monotonic()
    out, rc = run_curl(["--socks5-hostname", proxy, "-X", "POST",
                        "--data-binary", "@" + upload_file,
                        "-o", "/dev/null", "-w", "%{http_code}",
                        UPLOAD_URL], UPLOAD_TIMEOUT)
    dt = time.monotonic() - t0
    if rc == 0 and (out or "").strip() == "200":
        return os.path.getsize(upload_file), dt
    return 0, dt


def speedtest_download(proxy):
    """Скорость скачивания как у Speedtest: SPEED_STREAMS параллельных
    потоков по 10 МБ. Возвращает Мбит/с (суммарные байты / общее время)."""
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=SPEED_STREAMS) as ex:
        results = list(ex.map(_download_one,
                              [(proxy, SPEED_URL)] * SPEED_STREAMS))
    dt = time.monotonic() - t0
    # Если Cloudflare не отдал ни байта ни в одном потоке — пробуем CacheFly.
    total = sum(b for b, _ in results)
    if total <= 0:
        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=SPEED_STREAMS) as ex:
            results = list(ex.map(_download_one,
                                  [(proxy, SPEED_FALLBACK)] * SPEED_STREAMS))
        dt = time.monotonic() - t0
        total = sum(b for b, _ in results)
    if total > 1_000_000 and dt > 0:
        return round((total * 8 / 1e6) / dt, 1)
    return 0.0


def speedtest_upload(proxy, upload_file):
    """Скорость аплоада как у Speedtest: SPEED_STREAMS параллельных
    POST-потоков по 10 МБ. Возвращает Мбит/с."""
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=SPEED_STREAMS) as ex:
        results = list(ex.map(_upload_one,
                              [(proxy, upload_file)] * SPEED_STREAMS))
    dt = time.monotonic() - t0
    total = sum(b for b, _ in results)
    if total > 1_000_000 and dt > 0:
        return round((total * 8 / 1e6) / dt, 1)
    return 0.0


def speed_stage(xray_bin, node, socks_port, tmpdir, upload_file, ping_res):
    """Этап 2: мультипоточный замер скорости (один раз, как Speedtest).
    ping_res — результат этапа 1 (для переноса пинг-статистики)."""
    res = dict(ping_res)
    res["speed_mbps"] = 0.0
    res["upload_mbps"] = 0.0
    proc = start_xray(xray_bin, node, socks_port, tmpdir)
    if proc is None:
        res["status"] = "DEAD"
        return res
    try:
        proxy = "socks5h://127.0.0.1:%d" % socks_port
        res["speed_mbps"] = speedtest_download(proxy)
        if upload_file and os.path.exists(upload_file):
            res["upload_mbps"] = speedtest_upload(proxy, upload_file)
        res["status"] = "OK"
        return res
    finally:
        stop_xray(proc)


def qstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def emit_yaml(node):
    L = [f"- name: {qstr(node['name'])}", f"  type: {node['type']}",
         f"  server: {node['server']}", f"  port: {node['port']}"]
    if node["type"] == "vless":
        L += [f"  uuid: {node['uuid']}", "  udp: true",
              f"  network: {node.get('network', 'tcp')}", "  tls: true"]
        if node.get("sni"):
            L.append(f"  servername: {node['sni']}")
        if node.get("flow"):
            L.append(f"  flow: {node['flow']}")
        if node.get("fp"):
            L.append(f"  client-fingerprint: {node['fp']}")
        L += ["  reality-opts:",
              f"    public-key: {node['pbk']}",
              f"    short-id: {node['sid']}"]
    else:
        L += [f"  cipher: {qstr(node['cipher'])}",
              f"  password: {qstr(node['password'])}", "  udp: true"]
    return "\n".join(L)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--xray", default="xray")
    ap.add_argument("--b64", default="dobro.b64")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--tmpdir", default="/tmp/dobro-health")
    args = ap.parse_args()

    os.makedirs(args.tmpdir, exist_ok=True)
    nodes = load_nodes(args.b64)
    print(f"nodes in subscription: {len(nodes)}")
    status = fetch_status()
    up_relaxed = fetch_status_relaxed(status)
    print(f"uptime >= {MIN_UPTIME}% (30d, no games/LTE) on status site: {len(up_relaxed)}")

    candidates, skipped = [], 0
    for n in nodes:
        if normalize(n["name"]) in up_relaxed:
            candidates.append(n)
        else:
            skipped += 1
    print(f"candidates (uptime >= {MIN_UPTIME}%): {len(candidates)}; "
          f"skipped (below {MIN_UPTIME}%): {skipped}")

    # --- RU-гарантия: лучшие RU-узлы подписки по d30 (сверху вниз), без дублей
    # с основным списком. RU-узлы освобождены от порогов скорости MIN_SPEED /
    # MIN_UPLOAD: проходят по живому тесту, но обязаны пройти этап 1
    # (пинг/стабильность) и замер скорости.
    main_names = {normalize(n["name"]) for n in candidates}
    ru_pool = []
    for n in nodes:
        norm = normalize(n["name"])
        if norm in main_names:
            continue
        s = status.get(norm)
        if s and is_ru(norm) and s["group"] != "games" \
                and "lte" not in norm.lower():
            ru_pool.append((s["up"].get("d30") or 0, n))
    ru_pool.sort(key=lambda t: -t[0])
    print(f"RU pool (by d30 desc): {len(ru_pool)}: " +
          ", ".join(f"{n['name']} d30={d}" for d, n in ru_pool))

    # Файл аплоад-пробы (10 МБ случайных данных на поток) — создаётся один раз.
    upload_file = os.path.join(args.tmpdir, "upload-10mb.bin")
    if not os.path.exists(upload_file) or os.path.getsize(upload_file) != UPLOAD_SIZE:
        with open(upload_file, "wb") as f:
            f.write(os.urandom(UPLOAD_SIZE))
    print(f"upload probe: {upload_file} ({UPLOAD_SIZE} bytes)")

    node_by_key = {}
    for n in candidates:
        node_by_key[normalize(n["name"])] = n
    for _, n in ru_pool:
        node_by_key.setdefault(normalize(n["name"]), n)

    port = 19000
    ping_results = {}  # norm-имя -> результат этапа 1

    def run_ping(node, idx, total, tag=""):
        nonlocal port
        port += 1
        print(f"[{idx}/{total}]{tag} {node['name']} ...", flush=True)
        r = ping_stage(args.xray, node, port, args.tmpdir)
        r["link"] = node["link"]
        r["node"] = node
        r["ru"] = is_ru(normalize(node["name"]))
        r["d30"] = status.get(normalize(node["name"]), {}).get("up", {}).get("d30")
        ping_results[normalize(node["name"])] = r
        print(f"    -> {r['status']} exit={r['exit_ip']} "
              f"ping_med={r['ping_med']}ms jit={r['ping_jit']}ms "
              f"max={r['ping_max']}ms probes={r['ping_probes']}", flush=True)
        return r

    # --- Этап 1: пинг всех кандидатов (5 проб, пауза 3 с) ---
    for i, node in enumerate(candidates, 1):
        run_ping(node, i, len(candidates), tag=" [PING]")
    # RU, этап 1: тестируем весь пул (он маленький) — буфер на случай,
    # если кто-то не пройдёт фильтр джиттера.
    for j, (d30, node) in enumerate(ru_pool, 1):
        run_ping(node, j, len(ru_pool), tag=" [RU PING]")
    print(f"Ping stage done: {len(ping_results)} tested", flush=True)

    # --- Отбор по этапу 1: стабильный пинг (джиттер + без скачков) ---
    stable = [k for k, r in ping_results.items()
              if r["status"] == "OK"]
    unstable = [k for k, r in ping_results.items()
                if r["status"] == "UNSTABLE"]
    dead = [k for k, r in ping_results.items()
            if r["status"] in ("DEAD", "FLAKY")]
    print(f"Ping filter: stable {len(stable)} | unstable (jitter/spike) "
          f"{len(unstable)} | dead {len(dead)}", flush=True)

    # RU-добор: если стабильных RU меньше цели — добираем RU-узлы с
    # наименьшим джиттером (с рабочим туннелем), они помечаются в таблице.
    ru_stable_n = sum(1 for k in stable if ping_results[k].get("ru"))
    ru_fallback = []
    if ru_stable_n < RU_TARGET:
        ru_unstable = [ping_results[k] for k in unstable
                       if ping_results[k].get("ru")
                       and ping_results[k]["ping_jit"] is not None]
        ru_unstable.sort(key=lambda r: (r["ping_jit"], r["ping_med"]))
        need = RU_TARGET - ru_stable_n
        ru_fallback = [r["norm"] for r in ru_unstable[:need]]
        print(f"RU fallback: {len(ru_fallback)} unstable RU nodes added "
              f"(lowest jitter): {ru_fallback}", flush=True)

    # --- Этап 2: скорость (один раз, мультипоток) для отобранных ---
    speed_keys = stable + [k for k in ru_fallback if k not in stable]
    speed_results = {}
    for idx, key in enumerate(speed_keys, 1):
        node = node_by_key.get(key)
        if node is None:
            continue
        port += 1
        print(f"[{idx}/{len(speed_keys)}] [SPEED] {node['name']} ...", flush=True)
        r = speed_stage(args.xray, node, port, args.tmpdir, upload_file,
                        ping_results[key])
        r["ru_fallback"] = key in ru_fallback
        speed_results[key] = r
        print(f"    -> {r['status']} down={r['speed_mbps']} "
              f"up={r['upload_mbps']} Mbps", flush=True)

    # --- Финал: прошли оба этапа ---
    def speed_pass(r):
        """Замер скорости пройден: живой тест OK, и (для не-RU) скачивание
        >= MIN_SPEED и аплоад >= MIN_UPLOAD. RU проходят по живому тесту."""
        if r["status"] != "OK":
            return False
        if r.get("ru"):
            return True
        return ((r["speed_mbps"] or 0) >= MIN_SPEED
                and (r["upload_mbps"] or 0) >= MIN_UPLOAD)

    ok, slow = [], []
    for key, r in speed_results.items():
        if not speed_pass(r):
            slow.append(r)  # живой тест OK, но ниже порога скорости
            continue
        ok.append(r)

    # Ранжирование: сначала по скорости скачивания (больше — лучше),
    # потом по медиане пинга (меньше — лучше).
    ok.sort(key=lambda r: (-(r["speed_mbps"] or 0),
                           (r["ping_med"] if r["ping_med"] is not None else 1e9)))
    ru_ok_n = sum(1 for r in ok if r.get("ru"))
    print(f"FINAL OK: {len(ok)} (stable ping + down >= {MIN_SPEED}, "
          f"up >= {MIN_UPLOAD}) | too slow: {len(slow)} | "
          f"unstable ping: {len(unstable)} | dead: {len(dead)}")

    if not ok:
        print("WARNING: no node passed — keeping previous relaxed files untouched")
        return 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # --- dobro-relaxed.yaml (Clash) ---
    names = [qstr(r["node"]["name"]) for r in ok]
    out = ["# dobro-relaxed.yaml — auto-generated, do not edit manually",
           f"# updated: {now} | relaxed: {len(ok)} of {len(ping_results)} tested "
           f"(uptime >= {MIN_UPTIME}% 30d + TWO-STAGE live check: stage 1 ping "
           f"{PING_PROBES}x, {PING_GAP_SECONDS}s apart, jitter <= {MAX_JITTER}ms, "
           f"no spikes (max <= median x {SPIKE_FACTOR}); stage 2 speedtest-like "
           f"({SPEED_STREAMS} parallel streams) down >= {MIN_SPEED} Mbps "
           f"+ up >= {MIN_UPLOAD} Mbps; includes {ru_ok_n} RU nodes by the RU guarantee)",
           f"# Relaxed pool: nodes with >= 90% 30-day uptime on status.azmov.site AND "
           f"a passing TWO-STAGE live REALITY tunnel test (stage 1: stable ping, "
           f"stage 2: speedtest-like speed down >= {MIN_SPEED} Mbps AND up >= "
           f"{MIN_UPLOAD} Mbps, measured ONCE) (RU nodes exempt from the speed floors "
           "by the RU guarantee, but must pass stage 1). Ranked by download speed "
           "(highest first), then by median ping (lowest first). Games and LTE excluded.",
           "", "port: 7890", "socks-port: 7891", "mixed-port: 7892",
           "allow-lan: false", "mode: rule", "log-level: info", "ipv6: false",
           "", "proxies:"]
    out += [emit_yaml(r["node"]) for r in ok]
    out += ["", "proxy-groups:", "- name: AUTO", "  type: url-test",
            "  url: https://www.gstatic.com/generate_204", "  interval: 300",
            "  tolerance: 50", "  lazy: true", "  proxies:"]
    out += [f"  - {n}" for n in names]
    out += ["", "- name: SELECT", "  type: select", "  proxies:",
            "  - AUTO", "  - DIRECT", "", "rules:",
            "- GEOIP,private,DIRECT,no-resolve", "- MATCH,SELECT", ""]
    with open(os.path.join(args.out_dir, "dobro-relaxed.yaml"), "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    # --- dobro-relaxed.txt (base64-список ссылок) ---
    links = [r["node"]["link"] for r in ok]
    with open(os.path.join(args.out_dir, "dobro-relaxed.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii"))
    # --- dobro-relaxed.md (отчёт) ---
    md = [f"# DobroVPN relaxed — {now}", "",
          f"Прошли проверку: **{len(ok)}** из {len(ping_results)} протестированных "
          f"(аптайм >= {MIN_UPTIME}% за 30 дней + ДВУХЭТАПНАЯ проверка: этап 1 — "
          f"пинг {PING_PROBES} раз с паузой {PING_GAP_SECONDS} с, джиттер <= "
          f"{MAX_JITTER} мс, без скачков (макс. <= медиана x {SPIKE_FACTOR}); "
          f"этап 2 — скорость как у Speedtest ({SPEED_STREAMS} параллельных "
          f"потока), скачивание >= {MIN_SPEED} Мбит/с и аплоад >= {MIN_UPLOAD} "
          f"Мбит/с, замер один раз). "
          f"RU-узлов в файле: **{ru_ok_n}** (цель {RU_TARGET}). "
          f"Ранжирование: сначала по скорости скачивания (больше — лучше), "
          f"потом по медиане пинга. Игровые и LTE исключены.", "",
          "| # | Узел | Пинг (мед.) | Джиттер | Макс. пинг | Скач. | Аплоад | Аптайм (30д) | Выходной IP |",
          "|---|------|-------------|---------|------------|-------|--------|--------------|-------------|"]
    for i, r in enumerate(ok, 1):
        site = f"RU {r['d30']}%" if r.get("ru") else f"{r['d30']}%"
        if r.get("ru_fallback"):
            site += " (джиттер выше порога)"
        md.append(f"| {i} | {r['name']} | {r['ping_med']} мс | "
                  f"{r['ping_jit']} мс | {r['ping_max']} мс | "
                  f"{r['speed_mbps']} Мбит/с | {r['upload_mbps']} Мбит/с | "
                  f"{site} | {r['exit_ip']} |")
    md += ["", "## Не прошли",
           f"DEAD: {len(dead)} | нестабильный пинг (джиттер/скачки): {len(unstable)} | "
           f"слишком медленные: {len(slow)}", ""]
    for k in dead:
        md.append(f"- {ping_results[k]['name']} — DEAD")
    for k in unstable:
        r = ping_results[k]
        md.append(f"- {r['name']} — unstable ping "
                  f"(med {r['ping_med']} / jit {r['ping_jit']} / "
                  f"max {r['ping_max']} мс, probes {r['ping_probes']})")
    for r in slow:
        md.append(f"- {r['name']} — too slow "
                  f"(down {r['speed_mbps']} / up {r['upload_mbps']} Мбит/с)")
    md.append("")
    with open(os.path.join(args.out_dir, "dobro-relaxed.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"wrote dobro-relaxed.yaml + dobro-relaxed.txt + dobro-relaxed.md: {len(ok)} nodes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
