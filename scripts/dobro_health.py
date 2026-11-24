#!/usr/bin/env python3
# ============================================================================
# dobro_health.py — "умный" health-check подписки ДоброВПН.
#
# Что делает:
#   1. Читает узлы из dobro.b64 (зеркало подписки в репозитории).
#   2. Качает https://status.azmov.site/data/status.json и строит множество
#      серверов со 100% аптаймом за 30 дней (d30 == 100.0).
#      Игровые (group == 'games') и LTE исключаются.
#   3. Кандидаты = узлы подписки, чьё нормализованное имя есть в 100%-множестве.
#   4. Каждый кандидат живо тестируется через xray-core на этом же хосте:
#      REALITY-handshake, выходной IP, задержка (api.ipify.org), скорость (~10 МБ).
#   5. В dobro-healthy.yaml и dobro-healthy.txt пишутся ТОЛЬКО узлы,
#      которые одновременно: 100% аптайм И прошли живую проверку.
#   6. Пишет отчёт dobro-healthy.md с таблицей результатов.
#
# Fail-closed: если живых узлов 0 — старые healthy-файлы НЕ перезаписываются.
# Запуск: python3 dobro_health.py [--xray /path/to/xray] [--out-dir .]
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


def fetch_status_100():
    """Множество имён серверов с d30 == 100.0, без games и LTE."""
    req = urllib.request.Request(STATUS_URL, headers={"User-Agent": "dobro-health/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    out = {}
    for s in data.get("servers", []):
        u = s.get("up") or {}
        if u.get("d30") == 100.0 and s.get("group") != "games" \
                and "lte" not in (s.get("name") or "").lower():
            out[s.get("name")] = s.get("group")
    return out


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


def test_node(xray_bin, node, socks_port, tmpdir):
    """Живой тест одного узла. Возвращает dict с результатами."""
    cfg_path = os.path.join(tmpdir, "xray-%d.json" % socks_port)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(xray_config(node, socks_port), f)
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {"name": node["name"], "norm": normalize(node["name"]),
           "type": node["type"], "status": "DEAD", "exit_ip": "",
           "lat_avg": None, "lat_min": None, "lat_max": None,
           "lat_std": None, "speed_mbps": 0.0}
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
        # 3) скорость: ~10 МБ через прокси
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
    up100 = fetch_status_100()
    print(f"100% uptime (30d, no games/LTE) on status site: {len(up100)}")

    candidates, skipped = [], 0
    for n in nodes:
        if normalize(n["name"]) in up100:
            candidates.append(n)
        else:
            skipped += 1
    print(f"candidates (100% uptime): {len(candidates)}; skipped (not 100%): {skipped}")

    results = []
    port = 19000
    for i, node in enumerate(candidates, 1):
        port += 1
        print(f"[{i}/{len(candidates)}] {node['name']} ...", flush=True)
        r = test_node(args.xray, node, port, args.tmpdir)
        r["link"] = node["link"]
        r["node"] = node
        results.append(r)
        print(f"    -> {r['status']} exit={r['exit_ip']} lat={r['lat_avg']}ms "
              f"std={r['lat_std']}ms speed={r['speed_mbps']} Mbps", flush=True)

    ok = [r for r in results if r["status"] == "OK"]
    # Сортировка: сначала OK по задержке, потом по скорости
    ok.sort(key=lambda r: ((r["lat_avg"] if r["lat_avg"] is not None else 1e9),
                           -(r["speed_mbps"] or 0)))
    print(f"OK: {len(ok)} | FLAKY: {sum(1 for r in results if r['status']=='FLAKY')} "
          f"| DEAD: {sum(1 for r in results if r['status']=='DEAD')}")

    if not ok:
        print("WARNING: no node passed — keeping previous healthy files untouched")
        return 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # --- dobro-healthy.yaml (Clash) ---
    names = [qstr(r["node"]["name"]) for r in ok]
    out = ["# dobro-healthy.yaml — auto-generated, do not edit manually",
           f"# updated: {now} | healthy: {len(ok)} of {len(candidates)} candidates "
           f"(100% uptime 30d + live check passed)",
           "# Only nodes with 100% 30-day uptime on status.azmov.site AND a passing "
           "live REALITY tunnel test. Games and LTE excluded.",
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
    with open(os.path.join(args.out_dir, "dobro-healthy.yaml"), "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    # --- dobro-healthy.txt (base64-список ссылок) ---
    links = [r["node"]["link"] for r in ok]
    with open(os.path.join(args.out_dir, "dobro-healthy.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii"))
    # --- dobro-healthy.md (отчёт) ---
    md = [f"# DobroVPN healthy — {now}", "",
          f"Прошли проверку: **{len(ok)}** из {len(candidates)} кандидатов "
          f"(100% аптайм 30 дней + живой тест). Игровые и LTE исключены.", "",
          "| # | Узел | Статус на сайте | Задержка | Джиттер | Скорость | Выходной IP |",
          "|---|------|----------------|----------|---------|----------|-------------|"]
    for i, r in enumerate(ok, 1):
        md.append(f"| {i} | {r['name']} | 100% (30д) | {r['lat_avg']} мс | "
                  f"{r['lat_std']} мс | {r['speed_mbps']} Мбит/с | {r['exit_ip']} |")
    md += ["", "## Не прошли",
           f"FLAKY: {sum(1 for r in results if r['status']=='FLAKY')} | "
           f"DEAD: {sum(1 for r in results if r['status']=='DEAD')}", ""]
    for r in results:
        if r["status"] != "OK":
            md.append(f"- {r['name']} — {r['status']}")
    md.append("")
    with open(os.path.join(args.out_dir, "dobro-healthy.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"wrote dobro-healthy.yaml + dobro-healthy.txt + dobro-healthy.md: {len(ok)} nodes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
