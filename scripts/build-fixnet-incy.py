#!/usr/bin/env python3
# build-fixnet-incy.py — FixNet subscription (plain vless links + happ routing blob)
#   -> fixnet-incy.json (INCY JSON array of per-node xray configs, same shape as
#      dobro-incy.json) + fixnet.txt (plain links, verbatim).
# Usage: python3 build-fixnet-incy.py <raw-subscription-text-file> <outdir>
# The input file is the raw panel response (links + happ://routing/add blob).
# It contains node credentials — delete it after conversion, never commit it.
# No subscription URL/token is written anywhere by this script.
import base64
import json
import re
import sys
from urllib.parse import parse_qs, unquote

ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def parse_link(link):
    body, _, frag = link[8:].partition("#")
    # fragment: "Name?serverDescription=<b64>"
    name_part, _, sd_part = frag.partition("?serverDescription=")
    name = unquote(name_part).strip()
    server_desc = ""
    if sd_part:
        try:
            server_desc = base64.b64decode(
                sd_part + "=" * (-len(sd_part) % 4)
            ).decode("utf-8", "replace")
        except Exception:
            server_desc = ""
    ui_host, _, query = body.partition("?")
    uuid, _, hostport = ui_host.partition("@")
    host, _, port = hostport.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return None
    q = parse_qs(query)
    g = lambda k, d="": q.get(k, [d])[0]
    extra = None
    extra_raw = g("extra")
    if extra_raw:
        try:
            extra = json.loads(extra_raw)
        except Exception:
            extra = None
    return {
        "name": name or "vless",
        "uuid": uuid,
        "host": host,
        "port": port,
        "flow": g("flow"),
        "net": g("type", "tcp"),
        "host_header": g("host"),
        "path": g("path", "/"),
        "mode": g("mode"),
        "extra": extra,
        "security": g("security", "none"),
        "fp": g("fp", "firefox"),
        "sni": g("sni"),
        "pbk": g("pbk", ""),
        "sid": g("sid", ""),
        "serverDescription": server_desc,
    }


def xray_element(node, routing):
    ss = {"network": node["net"]}
    if node["net"] == "xhttp":
        xh = {"path": node["path"] or "/"}
        if node["host_header"]:
            xh["host"] = node["host_header"]
        if node["mode"]:
            xh["mode"] = node["mode"]
        if node["extra"] is not None:
            xh["extra"] = node["extra"]
        ss["xhttpSettings"] = xh
    elif node["net"] == "ws":
        ws = {"path": node["path"] or "/"}
        if node["host_header"]:
            ws["headers"] = {"Host": node["host_header"]}
        ss["wsSettings"] = ws
    elif node["net"] == "grpc":
        ss["grpcSettings"] = {"serviceName": node["path"] or ""}
    ss["security"] = node["security"]
    if node["security"] == "reality":
        ss["realitySettings"] = {
            "serverName": node["sni"],
            "publicKey": node["pbk"],
            "shortId": node["sid"],
            "fingerprint": node["fp"] or "firefox",
        }
    elif node["security"] == "tls":
        ss["tlsSettings"] = {"serverName": node["sni"] or node["host"]}
    user = {"id": node["uuid"], "encryption": "none"}
    if node["flow"]:
        user["flow"] = node["flow"]
    return {
        "dns": {"servers": ["77.88.8.8", "1.1.1.1"], "queryStrategy": "UseIPv4"},
        "log": {"loglevel": "warning"},
        "routing": routing,
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {"allowTransparent": False},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": node["host"],
                            "port": node["port"],
                            "users": [user],
                        }
                    ]
                },
                "streamSettings": ss,
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIP"},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {"response": {"type": "http"}},
            },
        ],
        "remarks": node["name"],
        "meta": {"serverDescription": node["serverDescription"]},
    }


def routing_from_blob(blob):
    # Happ routing profile (decoded from happ://routing/add/<b64>).
    # DirectSites/DirectIp -> direct; GlobalProxy=true -> final catch-all proxy.
    rules = []
    direct_domains = list(blob.get("DirectSites") or [])
    if direct_domains:
        rules.append(
            {"type": "field", "domain": direct_domains, "outboundTag": "direct"}
        )
    direct_ips = list(blob.get("DirectIp") or [])
    if direct_ips:
        rules.append({"type": "field", "ip": direct_ips, "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
    return {
        "rules": rules,
        "domainMatcher": "hybrid",
        "domainStrategy": blob.get("DomainStrategy") or "IPIfNonMatch",
    }


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: build-fixnet-incy.py <raw-subscription-file> <outdir>")
    src, outdir = sys.argv[1], sys.argv[2]
    raw = open(src, encoding="utf-8", errors="replace").read()
    links = [l.strip() for l in raw.splitlines() if l.strip().startswith("vless://")]
    blob = None
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("happ://routing/add/"):
            b64 = s[len("happ://routing/add/"):]
            try:
                blob = json.loads(
                    base64.urlsafe_b64decode(
                        b64 + "=" * (-len(b64) % 4)
                    ).decode("utf-8", "replace")
                )
            except Exception as e:
                print(f"WARNING: routing blob undecodable ({e})", file=sys.stderr)
    nodes, skipped = [], 0
    seen = set()
    for link in links:
        n = parse_link(link)
        if not n:
            skipped += 1
            continue
        if n["uuid"] == ZERO_UUID or not n["host"] or "example.com" in n["host"]:
            skipped += 1
            continue
        key = (n["uuid"], n["host"], n["port"])
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        nodes.append(n)
    if blob is not None:
        routing = routing_from_blob(blob)
        routing_src = f"panel routing blob ({blob.get('Name', '?')})"
    else:
        # Fallback: same default as the Dobro panel's .ru -> direct.
        routing = {
            "rules": [
                {
                    "type": "field",
                    "domain": ["domain:ru", "domain:xn--p1ai"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "direct",
                },
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ],
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
        }
        routing_src = "DEFAULT fallback (no routing blob in subscription)"
    elements = [xray_element(n, routing) for n in nodes]
    import os

    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "fixnet-incy.json"), "w", encoding="utf-8") as f:
        json.dump(elements, f, ensure_ascii=False, indent=2)
    with open(os.path.join(outdir, "fixnet.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join("vless://" + l[8:] for l in links) + "\n")
    print(f"nodes: {len(nodes)} (skipped {skipped} of {len(links)} links)")
    print(f"routing: {routing_src}")
    print(f"elements: {len(elements)}")
    nets = sorted({n["net"] for n in nodes})
    print(f"networks: {nets}")
    hosts = sorted({n["host"] for n in nodes})
    print(f"entry hosts: {len(hosts)}")
    print(f"names unique: {len({n['name'] for n in nodes})}")


if __name__ == "__main__":
    main()
