#!/usr/bin/env python3
# ============================================================================
# build-clash-from-incy.py
# Конвертер: INCY JSON (dobro-incy.json / dobro-incy-raw — массив полных
# xray-конфигов, который панель отдаёт по User-Agent INCY) ->
# Clash/Mihomo YAML (dobro-vpn.yaml) для Karing и Clash Verge Rev.
#
# Сохраняет из оригинала:
#   - все vless-узлы (дедуп по uuid+server+port; имя — remarks элемента,
#     где узел является "proxy", иначе его tag),
#   - ss-узлы из dobro.b64 (в INCY JSON их нет — панель отдаёт ss только
#     в base64-ссылках),
#   - DNS (включая per-domain 77.88.8.8 для .ru/.su/.xn--p1ai/yandex/vk),
#   - routing (порядок правил как в xray; .ru -> direct, private -> direct,
#     push/Apple -> direct, Gemini/AI -> балансер B_GM, geoip:ru -> direct),
#   - группы-автвыборы (страны, Нейросети, Универсальный, failover).
#
# Использование:
#   python3 build-clash-from-incy.py [dobro-incy-raw] [dobro.b64] [dobro-vpn.yaml]
# Если JSON невалиден/отсутствует — печатает SKIP и завершается кодом 3,
# чтобы workflow откатился на старую генерацию из ссылок.
# ============================================================================
import base64
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote


def qstr(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def vless_from_outbound(o):
    try:
        vn = o["settings"]["vnext"][0]
        user = vn["users"][0]
    except Exception:
        return None
    p = {
        "name": o.get("tag", "vless"),
        "type": "vless",
        "server": vn["address"],
        "port": int(vn["port"]),
        "uuid": user["id"],
        "udp": True,
        "network": "tcp",
    }
    ss = o.get("streamSettings", {}) or {}
    net = ss.get("network", "tcp")
    p["network"] = net
    sec = ss.get("security", "none")
    flow = user.get("flow")
    if flow:
        p["flow"] = flow
    if sec == "tls":
        p["tls"] = True
        sni = ss.get("tlsSettings", {}).get("serverName")
        if sni:
            p["servername"] = sni
        alpn = ss.get("tlsSettings", {}).get("alpn")
        if alpn:
            p["alpn"] = alpn if isinstance(alpn, list) else [alpn]
    elif sec == "reality":
        p["tls"] = True
        rs = ss.get("realitySettings", {}) or {}
        if rs.get("serverName"):
            p["servername"] = rs["serverName"]
        fp = rs.get("fingerprint")
        if fp:
            p["client-fingerprint"] = fp
        p["reality-opts"] = {
            "public-key": rs.get("publicKey", ""),
            "short-id": rs.get("shortId", ""),
        }
    if net == "ws":
        ws = ss.get("wsSettings", {}) or {}
        w = {"path": ws.get("path", "/")}
        headers = ws.get("headers", {}) or {}
        if headers.get("Host"):
            w["headers"] = {"Host": headers["Host"]}
        p["ws-opts"] = w
    elif net == "grpc":
        gs = ss.get("grpcSettings", {}) or {}
        p["grpc-opts"] = {"grpc-service-name": gs.get("serviceName", "")}
    return p


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
    return {"name": name, "type": "ss", "server": host, "port": port,
            "cipher": method, "password": password, "udp": True}


def xray_domain_to_clash(d, action):
    if d.startswith("domain:"):
        return f"DOMAIN-SUFFIX,{d[7:]},{action}"
    if d.startswith("full:"):
        return f"DOMAIN,{d[5:]},{action}"
    if d.startswith("keyword:"):
        return f"DOMAIN-KEYWORD,{d[8:]},{action}"
    if d.startswith("regexp:"):
        pat = d[7:]
        if pat.endswith("$"):
            inner = pat[:-1]
            m2 = re.fullmatch(r"\.\*\\\.([A-Za-z0-9-]+)", inner)
            if m2:
                return f"DOMAIN-SUFFIX,{m2.group(1)},{action}"
            m3 = re.fullmatch(r"\(\.\+\\\.\)\?([A-Za-z0-9.\-]+)", inner.lstrip("^"))
            if m3:
                return f"DOMAIN-SUFFIX,{m3.group(1)},{action}"
        return f"DOMAIN-REGEX,{qstr(pat)},{action}"
    if d.startswith("geosite:"):
        return f"GEOSITE,{d[8:]},{action}"
    return None


def xray_ip_to_clash(ip, action):
    if ip.startswith("geoip:"):
        g = ip[6:]
        return f"GEOIP,{g.upper() if g != 'private' else 'private'},{action},no-resolve"
    if ip.startswith("geosite:"):
        return None
    return f"IP-CIDR,{ip},{action},no-resolve"


def translate_routing(rules, gm_group, main_group):
    out = []
    skipped = Counter()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        tag = rule.get("outboundTag")
        bal = rule.get("balancerTag")
        if bal:
            action = gm_group
        elif tag == "direct":
            action = "DIRECT"
        elif tag == "block":
            action = "REJECT"
        elif tag == "proxy":
            action = main_group
        elif tag is None and not bal:
            skipped["no-target"] += 1
            continue
        else:
            skipped[f"tag:{tag}"] += 1
            continue
        ips = rule.get("ip", []) or []
        for ip in ips:
            r = xray_ip_to_clash(ip, action)
            if r:
                out.append(r)
            else:
                skipped["ip"] += 1
        for d in rule.get("domain", []) or []:
            r = xray_domain_to_clash(d, action)
            if r:
                out.append(r)
            else:
                skipped["domain"] += 1
        if rule.get("port") or rule.get("protocol") or rule.get("network"):
            if not ips and not rule.get("domain"):
                skipped["port/proto/network"] += 1
        if rule.get("source"):
            skipped["source"] += 1
    return out, skipped


def translate_dns(dns):
    servers = dns.get("servers", []) or []
    default_ns = []
    policy = {}
    for s in servers:
        if isinstance(s, str):
            default_ns.append(s)
        elif isinstance(s, dict):
            addr = s.get("address")
            if not addr:
                continue
            for d in s.get("domains", []) or []:
                if d.startswith("regexp:"):
                    pat = d[7:]
                    m = re.fullmatch(r"\.\*\\\.([A-Za-z0-9-]+)\$", pat)
                    if m:
                        policy[f"+.{m.group(1)}"] = addr
                        continue
                    m2 = re.fullmatch(r"\(\.\+\\\.\)\?([A-Za-z0-9.\-]+)\$", pat.lstrip("^"))
                    if m2:
                        policy[f"+.{m2.group(1)}"] = addr
                        continue
                    policy[pat] = addr
                elif d.startswith("domain:"):
                    policy[f"+.{d[7:]}"] = addr
                elif d.startswith("full:"):
                    policy[d[5:]] = addr
                else:
                    policy[d] = addr
    if not default_ns:
        default_ns = ["8.8.8.8", "8.8.4.4"]
    return default_ns, policy


def emit(p):
    L = [f"- name: {qstr(p['name'])}", f"  type: {p['type']}",
         f"  server: {p['server']}", f"  port: {p['port']}"]
    if p["type"] == "vless":
        L += [f"  uuid: {p['uuid']}", "  udp: true", f"  network: {p['network']}"]
        if p.get("tls"):
            L.append("  tls: true")
        if p.get("servername"):
            L.append(f"  servername: {p['servername']}")
        if p.get("flow"):
            L.append(f"  flow: {p['flow']}")
        if p.get("client-fingerprint"):
            L.append(f"  client-fingerprint: {p['client-fingerprint']}")
        if p.get("alpn"):
            L.append(f"  alpn: [{', '.join(p['alpn'])}]")
        if "reality-opts" in p:
            L += ["  reality-opts:",
                  f"    public-key: {p['reality-opts']['public-key']}",
                  f"    short-id: {p['reality-opts']['short-id']}"]
        if "grpc-opts" in p:
            L += ["  grpc-opts:",
                  f"    grpc-service-name: {qstr(p['grpc-opts']['grpc-service-name'])}"]
        if "ws-opts" in p:
            L += ["  ws-opts:", f"    path: {qstr(p['ws-opts']['path'])}"]
            if "headers" in p["ws-opts"]:
                L.append("    headers:")
                for k, v in p["ws-opts"]["headers"].items():
                    L.append(f"      {k}: {qstr(v)}")
    elif p["type"] == "ss":
        L += [f"  cipher: {qstr(p['cipher'])}", f"  password: {qstr(p['password'])}", "  udp: true"]
    return "\n".join(L)


def main():
    src_json = sys.argv[1] if len(sys.argv) > 1 else "dobro-incy-raw"
    src_b64 = sys.argv[2] if len(sys.argv) > 2 else "dobro.b64"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "dobro-vpn.yaml"

    try:
        raw = open(src_json, encoding="utf-8").read()
        data = json.loads(raw)
        if not isinstance(data, list) or not data:
            raise ValueError("not a non-empty JSON array")
    except Exception as e:
        print(f"SKIP: {src_json} is not a usable INCY JSON ({type(e).__name__}: {e})")
        return 3

    canon = None
    for el in data:
        if isinstance(el, dict) and "Москва #12" in str(el.get("remarks", "")):
            canon = el
            break
    if canon is None:
        rout_counts = Counter(
            json.dumps(el.get("routing", {}), sort_keys=True)
            for el in data if isinstance(el, dict)
        )
        most = rout_counts.most_common(1)[0][0]
        for el in data:
            if json.dumps(el.get("routing", {}), sort_keys=True) == most:
                canon = el
                break
    if canon is None:
        print("SKIP: no usable element in JSON")
        return 3
    print(f"canonical element: {canon.get('remarks')}")

    registry = {}
    order = []
    seen_names = set()

    def reg_name(base):
        name, i = base, 2
        while name in seen_names:
            name = f"{base} ({i})"
            i += 1
        seen_names.add(name)
        return name

    def register_vless(o, name_hint):
        p = vless_from_outbound(o)
        if not p:
            return None
        key = (p["uuid"], p["server"], p["port"])
        if key in registry:
            return key
        p["name"] = reg_name(name_hint)
        registry[key] = p
        order.append(key)
        return key

    for el in data:
        if not isinstance(el, dict):
            continue
        rem = el.get("remarks", "") or "vless"
        for o in el.get("outbounds", []) or []:
            if isinstance(o, dict) and o.get("protocol") == "vless" and o.get("tag") == "proxy":
                register_vless(o, rem)
    for el in data:
        if not isinstance(el, dict):
            continue
        for o in el.get("outbounds", []) or []:
            if (isinstance(o, dict) and o.get("protocol") == "vless"
                    and o.get("tag") != "proxy" and str(o.get("tag", "")).startswith("gm-")):
                register_vless(o, o.get("tag", "vless"))
    for el in data:
        if not isinstance(el, dict):
            continue
        for o in el.get("outbounds", []) or []:
            if (isinstance(o, dict) and o.get("protocol") == "vless"
                    and o.get("tag") != "proxy" and not str(o.get("tag", "")).startswith("gm-")):
                register_vless(o, o.get("tag", "vless"))

    n_ss = 0
    try:
        b64raw = open(src_b64, encoding="utf-8").read().strip()
        dec = base64.b64decode(b64raw + "=" * (-len(b64raw) % 4)).decode("utf-8", "replace")
        for line in dec.splitlines():
            line = line.strip()
            if not line.startswith("ss://"):
                continue
            p = parse_ss(line)
            if not p:
                continue
            p["name"] = reg_name(p["name"])
            key = ("ss", p["name"])
            if key in registry:
                continue
            registry[key] = p
            order.append(key)
            n_ss += 1
    except Exception as e:
        print(f"note: ss from {src_b64} skipped ({type(e).__name__})")

    proxies = [registry[k] for k in order]
    print(f"proxies: {len(proxies)} (vless {len(proxies)-n_ss}, ss {n_ss})")

    def resolve_outbounds(el):
        names = []
        for o in el.get("outbounds", []) or []:
            if not isinstance(o, dict) or o.get("protocol") != "vless":
                continue
            p = vless_from_outbound(o)
            if not p:
                continue
            key = (p["uuid"], p["server"], p["port"])
            if key in registry:
                names.append(registry[key]["name"])
        return names

    all_names = [p["name"] for p in proxies]
    gm_names = []
    for o in canon.get("outbounds", []) or []:
        if isinstance(o, dict) and o.get("protocol") == "vless" and str(o.get("tag", "")).startswith("gm-")):
            p = vless_from_outbound(o)
            if not p:
                continue
            key = (p["uuid"], p["server"], p["port"])
            if key in registry and registry[key]["name"] not in gm_names:
                gm_names.append(registry[key]["name"])
    if not gm_names:
        gm_names = [n for n in all_names if n.startswith("gm-")]
    groups = []
    groups.append(("AUTO", "url-test", all_names))
    groups.append(("SELECT", "select", ["AUTO", "DIRECT"]))
    if gm_names:
        groups.append(("GM", "url-test", gm_names))
    for el in data:
        if not isinstance(el, dict):
            continue
        rem = (el.get("remarks", "") or "").strip()
        if not rem:
            continue
        has_proxy = any(isinstance(o, dict) and o.get("tag") == "proxy"
                        for o in el.get("outbounds", []) or [])
        if has_proxy:
            continue
        members = resolve_outbounds(el)
        if len(members) < 2:
            continue
        gname = rem
        if gname in seen_names:
            gname = reg_name(gname)
        else:
            seen_names.add(gname)
        groups.append((gname, "url-test", members))
    print(f"groups: {len(groups)} (AUTO, SELECT, GM + {len(groups)-3} auto-select)")

    dns = canon.get("dns", {}) or {}
    default_ns, policy = translate_dns(dns)
    print(f"dns: nameserver={default_ns}, policy entries={len(policy)}")

    rules = (canon.get("routing", {}) or {}).get("rules", []) or []
    clash_rules, skipped = translate_routing(rules, "GM" if gm_names else "SELECT", "SELECT")
    print(f"routing: xray rules={len(rules)} -> clash rules={len(clash_rules)}, skipped={dict(skipped)}")
    has_ru_suffix = any(r == "DOMAIN-SUFFIX,ru,DIRECT" for r in clash_rules)
    has_ru_geoip = any(r.startswith("GEOIP,RU,DIRECT") for r in clash_rules)
    n_direct = sum(1 for r in clash_rules if ",DIRECT" in r)
    print(f"rules to DIRECT: {n_direct} | DOMAIN-SUFFIX,ru: {has_ru_suffix} | GEOIP,RU: {has_ru_geoip}")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    out += ["# dobro-vpn.yaml — auto-generated FULL config from INCY JSON, do not edit manually",
            f"# updated: {now} | source: dobro-incy.json (panel response to INCY UA)",
            f"# proxies: {len(proxies)} | groups: {len(groups)} | rules: {len(clash_rules) + 1} | dns policy: {len(policy)}",
            "# Routing + DNS preserved from the original panel config (.ru -> direct).",
            "# Import as a Clash/Mihomo profile in Karing or Clash Verge Rev.",
            "",
            "port: 7890",
            "socks-port: 7891",
            "mixed-port: 7892",
            "allow-lan: false",
            "mode: rule",
            "log-level: info",
            "ipv6: false",
            "",
            "dns:",
            "  enable: true",
            "  ipv6: false",
            "  nameserver:"]
    for ns in default_ns:
        out.append(f"    - {ns}")
    if policy:
        out.append("  nameserver-policy:")
        for dom, srv in sorted(policy.items()):
            out.append(f"    {qstr(dom)}: {srv}")
    out += ["  fallback:",
            "    - 8.8.8.8",
            "    - 8.8.4.4",
            "",
            "proxies:"]
    out += [emit(p) for p in proxies]
    out += ["",
            "proxy-groups:"]
    for gname, gtype, members in groups:
        out.append(f"- name: {qstr(gname)}")
        out.append(f"  type: {gtype}")
        if gtype == "url-test":
            out += ["  url: https://www.gstatic.com/generate_204",
                    "  interval: 300",
                    "  tolerance: 50",
                    "  lazy: true"]
        out.append("  proxies:")
        for m in members:
            out.append(f"  - {qstr(m)}")
    out += ["",
            "rules:"]
    for r in clash_rules:
        out.append(f"- {r}")
    out.append("- MATCH,SELECT")
    out.append("")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"wrote {out_path}: {len(proxies)} proxies, {len(groups)} groups, {len(clash_rules)} rules + MATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
