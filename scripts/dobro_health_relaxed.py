#!/usr/bin/env python3
# ============================================================================
# dobro_health_relaxed.py — "расслабленная" версия health-check подписки ДоброВПН.
#
# Отличие от строгой версии (dobro_health.py):
#   - НЕ требует 100% аптайм. Берутся узлы с d30 >= 90% (MIN_UPTIME).
#     Это даёт ~96 кандидатов вместо 15 — большой пул для выбора лучших.
#   - ДВОЙНОЙ ТЕСТ скорости: каждый узел тестируется ДВАЖДЫ — скачивание
#     + аплоад — с паузой ROUND_GAP_SECONDS (3 мин) между раундами.
#     В файл попадают ТОЛЬКО узлы, прошедшие ОБА раунда. Это отсекает
#     узлы с нестабильной скоростью (быстрые один раз, медленные — второй).
#   - Ранжирование: сначала по ГАРАНТИРОВАННОЙ скорости (минимум
#     скачивания за оба раунда, больше — лучше), потом по задержке
#     (меньше — лучше). Строгая версия ранжирует наоборот (сначала задержка).
#   - Узлы со скоростью ниже MIN_SPEED (скачивание, 50 Мбит/с) или
#     MIN_UPLOAD (аплоад, 50 Мбит/с — тот же порог) в файл НЕ попадают. RU-гарантия —
#     исключение: RU-узлы проходят по живому тесту без порога скорости
#     (самый быстрый RU в прогоне 25.11.2026 — 42,4 Мбит/с, порог 50 он
#     не проходит), но обязаны пройти ОБА раунда.
#   - RU-гарантия сохранена: лучшие RU-узлы (Москва/Новосибирск) обязательно
#     тестируются, пока не наберётся RU_TARGET=3 прошедших.
#
# Что делает (как строгая версия):
#   1. Читает узлы из dobro.b64 (зеркало подписки в репозитории).
#   2. Качает https://status.azmov.site/data/status.json и берёт серверы
#      с d30 >= MIN_UPTIME. Игровые (group == 'games') и LTE исключаются.
#   3. Каждый кандидат живо тестируется через xray-core на этом же хосте:
#      раунд 1 (все), пауза 3 мин, раунд 2 (только прошедшие раунд 1).
#   4. В dobro-relaxed.yaml и dobro-relaxed.txt пишутся ТОЛЬКО узлы,
#      которые прошли ОБА раунда (живой тест + пороги скорости).
#   5. Пишет отчёт dobro-relaxed.md с таблицей результатов (оба раунда).
#
# Fail-closed: если живых узлов 0 — старые relaxed-файлы НЕ перезаписываются.
# Запуск: python3 dobro_health_relaxed.py [--xray /path/to/xray] [--out-dir .]
# Требует: xray-core (скачивается workflow), curl, python3.
# ============================================================================
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote

STATUS_URL = "https://status.azmov.site/data/status.json"
IPIFY_URL = "https://api.ipify.org"
# Маленький файл для замера скорости (10 МБ). Cloudflare __down на больших
# размерах отдаёт 403 после частых запросов, поэтому только 10 МБ.
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
SPEED_FALLBACK = "https://cachefly.cachefly.net/10mb.test"
# Аплоад: POST 10 МБ на Cloudflare __up (тот же эндпоинт, что у speed-теста).
UPLOAD_URL = "https://speed.cloudflare.com/__up"
UPLOAD_SIZE = 10_000_000  # 10 МБ аплоад-пробы
UPLOAD_TIMEOUT = 60
LATENCY_PROBES = 6
LATENCY_TIMEOUT = 15
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
MIN_SPEED = 50.0  # минимальная скорость СКАЧИВАНИЯ, Мбит/с — медленнее в файл не попадает (кроме RU-гарантии: RU-узлы проходят по живому тесту без порога скорости, т.к. самый быстрый RU — 42,4 Мбит/с)
MIN_UPLOAD = 50.0  # минимальная скорость АПЛОАДА, Мбит/с — тот же порог, что и у скачивания (по просьбе Георгия 25.11.2026 «аплоад тоже 50+»).
ROUND_GAP_SECONDS = 180  # пауза между раундом 1 и раундом 2 (3 мин) — двойной тест скорости


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


def test_node(xray_bin, node, socks_port, tmpdir, upload_file=None):
    """Живой тест одного узла: выходной IP, задержка, скачивание, аплоад.
    Возвращает dict с результатами (speed_mbps — скачивание, upload_mbps — аплоад)."""
    cfg_path = os.path.join(tmpdir, "xray-%d.json" % socks_port)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(xray_config(node, socks_port), f)
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {"name": node["name"], "norm": normalize(node["name"]),
           "type": node["type"], "status": "DEAD", "exit_ip": "",
           "lat_avg": None, "lat_min": None, "lat_max": None,
           "lat_std": None, "speed_mbps": 0.0, "upload_mbps": 0.0}
    try:
        # Ждём, пока SOCKS-порт начнёт слушать (до 20 с), а не фиксированный sleep:
        # xray с REALITY стартует не мгновенно, и curl к ещё не поднятому порту
        # даёт мгновенный connection refused вместо таймаута.
        import socket
        deadline = time.monotonic() + 20
        up = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return res  # xray умер сразу — узел мёртв
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=1):
                    up = True
                    break
            except OSError:
                time.sleep(0.5)
        if not up:
            return res
        time.sleep(2)  # дать xray завершить инициализацию
        proxy = "socks5h://127.0.0.1:%d" % socks_port
        # 1) выходной IP (подтверждает, что туннель работает)
        out, rc = run_curl(["--socks5-hostname", proxy, IPIFY_URL], IP_TIMEOUT)
        if rc != 0 or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", out or ""):
            return res
        res["exit_ip"] = out
        # 2) задержка: время ответа ipify (работает через туннель)
        ts = []
        for _ in range(LATENCY_PROBES):
            t0 = time.monotonic()
            _, rc = run_curl(["--socks5-hostname", proxy, IPIFY_URL], LATENCY_TIMEOUT)
            dt = (time.monotonic() - t0) * 1000.0
            if rc == 0:
                ts.append(dt)
        if not ts:
            res["status"] = "FLAKY"
            return res
        avg = sum(ts) / len(ts)
        var = sum((x - avg) ** 2 for x in ts) / len(ts)
        res.update({"lat_avg": round(avg, 1), "lat_min": round(min(ts), 1),
                    "lat_max": round(max(ts), 1), "lat_std": round(var ** 0.5, 1)})
        # 3) скорость скачивания: ~10 МБ через прокси
        speed = None
        for url in (SPEED_URL, SPEED_FALLBACK):
            t0 = time.monotonic()
            out, rc = run_curl(["--socks5-hostname", proxy, "-o", "/dev/null",
                                "-w", "%{size_download}", url], SPEED_TIMEOUT)
            dt = time.monotonic() - t0
            if rc == 0 and out.isdigit() and int(out) > 1_000_000 and dt > 0:
                speed = (int(out) * 8 / 1e6) / dt
                break
        res["speed_mbps"] = round(speed, 1) if speed else 0.0
        # 4) скорость аплоада: POST 10 МБ на Cloudflare __up через прокси
        if upload_file and os.path.exists(upload_file):
            t0 = time.monotonic()
            out, rc = run_curl(["--socks5-hostname", proxy, "-X", "POST",
                                "--data-binary", "@" + upload_file,
                                "-o", "/dev/null", "-w", "%{http_code}",
                                UPLOAD_URL], UPLOAD_TIMEOUT)
            dt = time.monotonic() - t0
            if rc == 0 and (out or "").strip() == "200" and dt > 0:
                sz = os.path.getsize(upload_file)
                res["upload_mbps"] = round((sz * 8 / 1e6) / dt, 1)
        res["status"] = "OK"
        return res
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


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
    # MIN_UPLOAD: проходят по живому тесту, но обязаны пройти ОБА раунда.
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

    # Файл аплоад-пробы (10 МБ случайных данных) — создаётся один раз.
    upload_file = os.path.join(args.tmpdir, "upload-10mb.bin")
    if not os.path.exists(upload_file) or os.path.getsize(upload_file) != UPLOAD_SIZE:
        with open(upload_file, "wb") as f:
            f.write(os.urandom(UPLOAD_SIZE))
    print(f"upload probe: {upload_file} ({UPLOAD_SIZE} bytes)")

    def speed_pass(r):
        """Один раунд пройден: живой тест OK, и (для не-RU) скачивание
        >= MIN_SPEED и аплоад >= MIN_UPLOAD. RU проходят по живому тесту."""
        if r["status"] != "OK":
            return False
        if r.get("ru"):
            return True
        return ((r["speed_mbps"] or 0) >= MIN_SPEED
                and (r["upload_mbps"] or 0) >= MIN_UPLOAD)

    node_by_key = {}
    for n in candidates:
        node_by_key[normalize(n["name"])] = n
    for _, n in ru_pool:
        node_by_key.setdefault(normalize(n["name"]), n)

    results1 = {}  # norm-имя -> результат раунда 1
    results2 = {}  # norm-имя -> результат раунда 2
    port = 19000

    def run_one(node, idx, total, tag="", rnd=1):
        nonlocal port
        port += 1
        print(f"[{idx}/{total}]{tag} {node['name']} ...", flush=True)
        r = test_node(args.xray, node, port, args.tmpdir, upload_file)
        r["link"] = node["link"]
        r["node"] = node
        r["ru"] = is_ru(normalize(node["name"]))
        r["d30"] = status.get(normalize(node["name"]), {}).get("up", {}).get("d30")
        if rnd == 1:
            results1[normalize(node["name"])] = r
        else:
            results2[normalize(node["name"])] = r
        print(f"    -> {r['status']} exit={r['exit_ip']} lat={r['lat_avg']}ms "
              f"std={r['lat_std']}ms down={r['speed_mbps']} up={r['upload_mbps']} Mbps",
              flush=True)
        return r

    # --- Раунд 1: все кандидаты ---
    for i, node in enumerate(candidates, 1):
        run_one(node, i, len(candidates), tag=" [R1]", rnd=1)
    # RU, раунд 1: тестируем весь пул (он маленький) — буфер на случай,
    # если кто-то провалит раунд 2.
    for j, (d30, node) in enumerate(ru_pool, 1):
        run_one(node, j, len(ru_pool), tag=" [RU R1]", rnd=1)
    print(f"Round 1 done: {len(results1)} tested", flush=True)

    # --- Пауза 3 минуты между раундами ---
    print(f"Waiting {ROUND_GAP_SECONDS}s ({ROUND_GAP_SECONDS // 60} min) "
          f"before round 2 ...", flush=True)
    time.sleep(ROUND_GAP_SECONDS)

    # --- Раунд 2: только прошедшие раунд 1 ---
    r1_keys = [k for k, r in results1.items() if speed_pass(r)]
    print(f"Round 2: re-testing {len(r1_keys)} round-1 passers", flush=True)
    for idx, key in enumerate(r1_keys, 1):
        node = node_by_key.get(key)
        if node is None:
            continue
        run_one(node, idx, len(r1_keys), tag=" [R2]", rnd=2)

    # --- Финал: прошли ОБА раунда ---
    ok, flaky, slow, dead = [], [], [], []
    for key, r1 in results1.items():
        if r1["status"] != "OK":
            dead.append(r1)
            continue
        if not speed_pass(r1):
            slow.append(r1)  # живой тест OK, но ниже порога скорости в раунде 1
            continue
        r2 = results2.get(key)
        if r2 is None or r2["status"] != "OK" or not speed_pass(r2):
            flaky.append(r1)  # прошёл R1, провалил R2 — нестабилен
            continue
        merged = dict(r1)
        merged["speed2"] = r2["speed_mbps"]
        merged["upload2"] = r2["upload_mbps"]
        merged["lat2"] = r2["lat_avg"]
        # Гарантированные (худшие) скорости за оба раунда — ими ранжируем.
        merged["down_min"] = min(r1["speed_mbps"] or 0, r2["speed_mbps"] or 0)
        merged["up_min"] = min(r1["upload_mbps"] or 0, r2["upload_mbps"] or 0)
        ok.append(merged)

    # Ранжирование: сначала по гарантированному скачиванию (минимум за оба
    # раунда, больше — лучше), потом по задержке (меньше — лучше).
    ok.sort(key=lambda r: (-(r["down_min"] or 0),
                           (r["lat_avg"] if r["lat_avg"] is not None else 1e9)))
    ru_ok_n = sum(1 for r in ok if r.get("ru"))
    print(f"FINAL OK: {len(ok)} (both rounds, down >= {MIN_SPEED}, "
          f"up >= {MIN_UPLOAD}) | too slow R1: {len(slow)} | "
          f"flaky (R1 ok, R2 fail): {len(flaky)} | DEAD R1: {len(dead)}")

    if not ok:
        print("WARNING: no node passed both rounds — keeping previous relaxed files untouched")
        return 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # --- dobro-relaxed.yaml (Clash) ---
    names = [qstr(r["node"]["name"]) for r in ok]
    out = ["# dobro-relaxed.yaml — auto-generated, do not edit manually",
           f"# updated: {now} | relaxed: {len(ok)} of {len(results1)} tested "
           f"(uptime >= {MIN_UPTIME}% 30d + DOUBLE live check (2 rounds, "
           f"{ROUND_GAP_SECONDS // 60} min apart) + down >= {MIN_SPEED} Mbps "
           f"+ up >= {MIN_UPLOAD} Mbps; includes {ru_ok_n} RU nodes by the RU guarantee)",
           f"# Relaxed pool: nodes with >= 90% 30-day uptime on status.azmov.site AND "
           f"a passing DOUBLE live REALITY tunnel test (2 rounds, {ROUND_GAP_SECONDS // 60} min "
           f"apart) AND down >= {MIN_SPEED} Mbps AND up >= {MIN_UPLOAD} Mbps (RU nodes "
           "exempt from the speed floors by the RU guarantee, but must pass both rounds). "
           "Ranked by GUARANTEED download (min of both rounds, highest first), then by "
           "latency (lowest first). Games and LTE excluded.",
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
          f"Прошли проверку: **{len(ok)}** из {len(results1)} протестированных "
          f"(аптайм >= {MIN_UPTIME}% за 30 дней + ДВОЙНОЙ живой тест: 2 раунда "
          f"с паузой {ROUND_GAP_SECONDS // 60} мин + скачивание >= {MIN_SPEED} Мбит/с "
          f"и аплоад >= {MIN_UPLOAD} Мбит/с в ОБОИХ раундах). "
          f"RU-узлов в файле: **{ru_ok_n}** (цель {RU_TARGET}). "
          f"Ранжирование: сначала по гарантированному скачиванию (минимум за оба "
          f"раунда, больше — лучше), потом по задержке. "
          f"Игровые и LTE исключены.", "",
          "| # | Узел | Скач. R1 / R2 | Аплоад R1 / R2 | Задержка | Джиттер | Аптайм (30д) | Выходной IP |",
          "|---|------|---------------|---------------|----------|---------|--------------|-------------|"]
    for i, r in enumerate(ok, 1):
        site = f"RU {r['d30']}%" if r.get("ru") else f"{r['d30']}%"
        md.append(f"| {i} | {r['name']} | {r['speed_mbps']} / {r['speed2']} Мбит/с | "
                  f"{r['upload_mbps']} / {r['upload2']} Мбит/с | {r['lat_avg']} мс | "
                  f"{r['lat_std']} мс | {site} | {r['exit_ip']} |")
    md += ["", "## Не прошли",
           f"DEAD (раунд 1): {len(dead)} | слишком медленные (раунд 1): {len(slow)} | "
           f"нестабильные (прошли R1, провалили R2): {len(flaky)}", ""]
    for r in dead:
        md.append(f"- {r['name']} — DEAD")
    for r in slow:
        md.append(f"- {r['name']} — too slow R1 "
                  f"(down {r['speed_mbps']} / up {r['upload_mbps']} Мбит/с)")
    for r in flaky:
        r2 = results2.get(r["norm"])
        if r2 is not None:
            md.append(f"- {r['name']} — flaky "
                      f"(R1 down {r['speed_mbps']} / up {r['upload_mbps']}, "
                      f"R2 down {r2['speed_mbps']} / up {r2['upload_mbps']} Мбит/с)")
        else:
            md.append(f"- {r['name']} — flaky (R1 ok, R2 not tested)")
    md.append("")
    with open(os.path.join(args.out_dir, "dobro-relaxed.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"wrote dobro-relaxed.yaml + dobro-relaxed.txt + dobro-relaxed.md: {len(ok)} nodes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
