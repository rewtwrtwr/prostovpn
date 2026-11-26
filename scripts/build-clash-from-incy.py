#!/usr/bin/env python3
# ============================================================================
# build-clash-from-incy.py  (v2 — сохраняет ВСЕ варианты routing)
# Конвертер: INCY JSON (dobro-incy.json / dobro-incy-raw — массив полных
# xray-конфигов, который панель отдаёт по User-Agent INCY) ->
# Clash/Mihomo YAML для Karing и Clash Verge Rev.
#
# ПРИНЦИП (требование Георгия, 26.11.2026): если у владельцев 15 разных
# вариаций routing — в итоговом конфиге должно остаться 15 вариаций.
# Доказано данными: 81 домен маршрутизируется в РАЗНЫЕ балансеры в разных
# вариантах (gemini.google.com -> B_GM / B_AI / B_STICKY, notion.* ->
# B_UNI / Super_Balancer), а .ru-списки — не вложенные подмножества
# (173 / 224 / 251 домен). Один общий rules-список Clash НЕ МОЖЕТ выразить
# 15 независимых наборов правил, поэтому генерируется:
#   - dobro-vpn.yaml — единый конфиг (union правил, все узлы) — простой
#     вариант «один файл на всё»;
#   - dobro-vpn-variant-XX.yaml — по одному файлу на каждый из 15 точных
#     вариантов routing (свои DNS, свои правила, свои узлы и балансеры).
#
# Сохраняет из оригинала (в каждом variant-файле — своё):
#   - vless-узлы варианта (дедуп по uuid+server+port; имя — remarks
#     элемента, где узел является "proxy", иначе его tag),
#   - ss-узлы из dobro.b64 (в INCY JSON их нет),
#   - DNS варианта (включая per-domain 77.88.8.8 для .ru/.su/.xn--p1ai),
#   - routing варианта (порядок правил как в xray; .ru -> direct,
#     private -> direct, push/Apple -> direct, сервисы -> свои балансеры,
#     geoip:ru -> direct),
#   - группы-балансеры варианта (B_GM, B_AI, B_UNI, B_YT, B_TG, B_TT,
#     B_IG и авто-выборы стран/Нейросети/Универсальный/failover).
#
# Балансер -> члены: по префиксу tag исходящих узлов
#   B_GM->gm-, B_AI->ai-, B_UNI->uni-, B_YT->yt-, B_TG->tg-,
#   B_TT->tt-, B_IG->igr-. Балансеры без выводимых членов
#   (B_STICKY, B_WHITE_AUTO, Super_Balancer, AUDIT_RESCUE_*) мапятся
#   на SELECT (трафик идёт на выбранный пользователем прокси).
#   Правила AUDIT_RESCUE без доменов/IP (аудит, не маршрутизация)
#   пропускаются.
#
# Использование:
#   python3 build-clash-from-incy.py [dobro-incy-raw] [dobro.b64] [out-dir]
# out-dir по умолчанию "."; пишет dobro-vpn.yaml и dobro-vpn-variant-*.yaml.
# Если JSON невалиден/отсутствует — печатает SKIP, код 3 (workflow
# откатится на старую генерацию из ссылок).
# ============================================================================
import base64
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote

# balancerTag -> префикс tag исходящих узлов-членов
BALANCER_PREFIX = {
    "B_GM": "gm-",
    "B_AI": "ai-",
    "B_UNI": "uni-",
    "B_YT": "yt-",
    "B_TG": "tg-",
    "B_TT": "tt-",
    "B_IG": "igr-",
}

ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def qstr(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def vless_from_outbound(o):
    try:
        vn = o["settings"]["vnext"][0]
        user = vn["users"][0]
    except Exception:
        return None
    # 26.11.2026: узлы с нулевым UUID — плейсхолдеры панели, не работают.
    if user.get("id") == ZERO_UUID:
        return None
    ss = o.get("streamSettings", {}) or {}
    net = ss.get("network", "tcp")
    # 26.11.2026: xhttp НЕ выпускаем в Clash/Mihomo. Причины:
    # (1) Mihomo поддерживает xhttp только с v1.19.22 (апрель 2026),
    # версия ядра в Karing неизвестна и может быть старше;
    # (2) конвертер не переносил xhttpSettings (path/mode/host) —
    # узлы выходили без xhttp-opts, т.е. malformed. Серверы xhttp-узлов
    # дублируются tcp/grpc/ws-узлами тех же IP, потери нет.
    if net == "xhttp":
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


def translate_routing(rules, balancer_group, main_group):
    out = []
    skipped = Counter()
    used = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        tag = rule.get("outboundTag")
        bal = rule.get("balancerTag")
        has_matcher = bool(rule.get("domain") or rule.get("ip") or rule.get("port")
                           or rule.get("protocol") or rule.get("network")
                           or rule.get("source"))
        if bal:
            if bal.startswith("AUDIT_RESCUE") and not has_matcher:
                skipped["audit-no-matcher"] += 1
                continue
            action = balancer_group.get(bal) if balancer_group else None
            if not action:
                action = main_group
                skipped[f"balancer-unresolved:{bal}"] += 1
            else:
                used.add(bal)
        elif tag == "direct":
            action = "DIRECT"
        elif tag == "block":
            action = "REJECT"
        elif tag == "proxy":
            action = main_group
        elif tag is None:
            skipped["no-target"] += 1
            continue
        else:
            skipped[f"tag:{tag}"] += 1
            continue
        for ip in rule.get("ip", []) or []:
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
            if not rule.get("ip") and not rule.get("domain"):
                skipped["port/proto/network"] += 1
        if rule.get("source"):
            skipped["source"] += 1
    return out, skipped, used


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


class Registry:
    def __init__(self):
        self.map = {}
        self.order = []
        self.seen_names = set()

    def reg_name(self, base):
        name, i = base, 2
        while name in self.seen_names:
            name = f"{base} ({i})"
            i += 1
        self.seen_names.add(name)
        return name

    def add_vless(self, o, name_hint):
        p = vless_from_outbound(o)
        if not p:
            return None
        key = (p["uuid"], p["server"], p["port"])
        if key in self.map:
            return key
        p["name"] = self.reg_name(name_hint)
        self.map[key] = p
        self.order.append(key)
        return key

    def add_ss(self, p):
        p["name"] = self.reg_name(p["name"])
        key = ("ss", p["name"])
        if key in self.map:
            return None
        self.map[key] = p
        self.order.append(key)
        return key

    def name_of(self, o):
        p = vless_from_outbound(o)
        if not p:
            return None
        key = (p["uuid"], p["server"], p["port"])
        return self.map[key]["name"] if key in self.map else None


def build_yaml(proxies, groups, dns_ns, dns_policy, clash_rules, header_lines):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    out += header_lines
    out += [f"# updated: {now}",
            f"# proxies: {len(proxies)} | groups: {len(groups)} | rules: {len(clash_rules) + 1} | dns policy: {len(dns_policy)}",
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
    for ns in dns_ns:
        out.append(f"    - {ns}")
    if dns_policy:
        out.append("  nameserver-policy:")
        for dom, srv in sorted(dns_policy.items()):
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
    return "\n".join(out)


def main():
    src_json = sys.argv[1] if len(sys.argv) > 1 else "dobro-incy-raw"
    src_b64 = sys.argv[2] if len(sys.argv) > 2 else "dobro.b64"
    out_dir = sys.argv[3] if len(sys.argv) > 3 else "."
    os.makedirs(out_dir, exist_ok=True)

    try:
        raw = open(src_json, encoding="utf-8").read()
        data = json.loads(raw)
        if not isinstance(data, list) or not data:
            raise ValueError("not a non-empty JSON array")
    except Exception as e:
        print(f"SKIP: {src_json} is not a usable INCY JSON ({type(e).__name__}: {e})")
        return 3

    def routing_key(el):
        return json.dumps(el.get("routing", {}), sort_keys=True, ensure_ascii=False)

    variants = defaultdict(list)
    for el in data:
        if isinstance(el, dict):
            variants[routing_key(el)].append(el)
    vlist = sorted(variants.values(), key=len, reverse=True)
    m12_idx = None
    for i, els in enumerate(vlist):
        if any("Москва #12" in str(e.get("remarks", "")) for e in els):
            m12_idx = i
            break
    if m12_idx not in (None, 0):
        vlist.insert(0, vlist.pop(m12_idx))
    print(f"routing variants: {len(vlist)} (elements: {[len(v) for v in vlist]})")

    reg = Registry()
    for el in data:
        if not isinstance(el, dict):
            continue
        rem = el.get("remarks", "") or "vless"
        for o in el.get("outbounds", []) or []:
            if isinstance(o, dict) and o.get("protocol") == "vless" and o.get("tag") == "proxy":
                reg.add_vless(o, rem)
    for el in data:
        if not isinstance(el, dict):
            continue
        for o in el.get("outbounds", []) or []:
            if (isinstance(o, dict) and o.get("protocol") == "vless"
                    and o.get("tag") != "proxy" and str(o.get("tag", "")).startswith("gm-")):
                reg.add_vless(o, o.get("tag", "vless"))
    for el in data:
        if not isinstance(el, dict):
            continue
        for o in el.get("outbounds", []) or []:
            if (isinstance(o, dict) and o.get("protocol") == "vless"
                    and o.get("tag") != "proxy" and not str(o.get("tag", "")).startswith("gm-")):
                reg.add_vless(o, o.get("tag", "vless"))
    n_ss = 0
    try:
        b64raw = open(src_b64, encoding="utf-8").read().strip()
        dec = base64.b64decode(b64raw + "=" * (-len(b64raw) % 4)).decode("utf-8", "replace")
        for line in dec.splitlines():
            line = line.strip()
            if not line.startswith("ss://"):
                continue
            p = parse_ss(line)
            if p and reg.add_ss(p):
                n_ss += 1
    except Exception as e:
        print(f"note: ss from {src_b64} skipped ({type(e).__name__})")
    all_proxies = [reg.map[k] for k in reg.order]
    print(f"proxies total: {len(all_proxies)} (vless {len(all_proxies)-n_ss}, ss {n_ss})")

    def names_for_outbounds(els, tag_prefix=None):
        names = []
        for el in els:
            for o in el.get("outbounds", []) or []:
                if not isinstance(o, dict) or o.get("protocol") != "vless":
                    continue
                if tag_prefix and not str(o.get("tag", "")).startswith(tag_prefix):
                    continue
                n = reg.name_of(o)
                if n and n not in names:
                    names.append(n)
        return names

    def variant_nodes(els):
        names = []
        for el in els:
            for o in el.get("outbounds", []) or []:
                if not isinstance(o, dict) or o.get("protocol") != "vless":
                    continue
                n = reg.name_of(o)
                if n and n not in names:
                    names.append(n)
        return names

    dns_counts = Counter(json.dumps(el.get("dns", {}), sort_keys=True) for el in data if isinstance(el, dict))
    common_dns = json.loads(dns_counts.most_common(1)[0][0])

    variant_files = []
    for vi, els in enumerate(vlist, start=1):
        rep = els[0]
        v_dns_counts = Counter(json.dumps(e.get("dns", {}), sort_keys=True) for e in els)
        v_dns = json.loads(v_dns_counts.most_common(1)[0][0])
        dns_ns, dns_policy = translate_dns(v_dns)
        rules = (rep.get("routing", {}) or {}).get("rules", []) or []
        used_balancers = set()
        for rule in rules:
            if isinstance(rule, dict) and rule.get("balancerTag"):
                used_balancers.add(rule["balancerTag"])
        bal_groups = {}
        bal_members = {}
        for bal in sorted(used_balancers):
            pref = BALANCER_PREFIX.get(bal)
            if not pref:
                continue
            members = names_for_outbounds(data, tag_prefix=pref)
            if members:
                bal_groups[bal] = bal
                bal_members[bal] = members
        v_nodes = variant_nodes(els)
        auto_members = v_nodes
        if not auto_members:
            for members in bal_members.values():
                auto_members = list(dict.fromkeys(auto_members + members))
        groups = []
        if auto_members:
            groups.append(("AUTO", "url-test", auto_members))
        sel_members = (["AUTO", "DIRECT"] if auto_members
                       else [b for b in sorted(bal_members)] + ["DIRECT"])
        groups.append(("SELECT", "select", sel_members))
        for bal in sorted(bal_members):
            groups.append((bal, "url-test", bal_members[bal]))
        for el in els:
            rem = (el.get("remarks", "") or "").strip()
            if not rem:
                continue
            has_proxy = any(isinstance(o, dict) and o.get("tag") == "proxy"
                            for o in el.get("outbounds", []) or [])
            if has_proxy:
                continue
            members = names_for_outbounds([el])
            if len(members) < 2:
                continue
            gname = rem
            if gname in reg.seen_names:
                gname = reg.reg_name(gname)
            else:
                reg.seen_names.add(gname)
            groups.append((gname, "url-test", members))
        clash_rules, skipped, used_bal = translate_routing(rules, bal_groups, "SELECT")
        has_ru = any(r == "DOMAIN-SUFFIX,ru,DIRECT" for r in clash_rules)
        has_geo = any(r.startswith("GEOIP,RU,DIRECT") for r in clash_rules)
        v_proxy_names = set(v_nodes)
        for members in bal_members.values():
            v_proxy_names.update(members)
        v_proxies = [p for p in all_proxies if p["name"] in v_proxy_names or p["type"] == "ss"]
        fname = f"dobro-vpn-variant-{vi:02d}.yaml"
        header = [
            "# " + fname + " — Clash/Mihomo config for ONE routing variant, do not edit manually",
            f"# variant {vi}/{len(vlist)} | elements: {len(els)} | xray rules: {len(rules)} -> clash rules: {len(clash_rules)}",
            "# nodes in this variant: " + ", ".join(sorted(set(
                e.get("remarks", "") for e in els if e.get("remarks")) )[:8]) + (" ..." if len(els) > 8 else ""),
            "# Routing + DNS preserved exactly as the panel configured them for these nodes.",
            "# Import as a Clash/Mihomo profile in Karing or Clash Verge Rev.",
        ]
        text = build_yaml(v_proxies, groups, dns_ns, dns_policy, clash_rules, header)
        with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as f:
            f.write(text)
        variant_files.append(fname)
        print(f"variant {vi:02d}: elements={len(els)} proxies={len(v_proxies)} "
              f"groups={len(groups)} rules={len(clash_rules)} .ru={has_ru} GEOIP-RU={has_geo} "
              f"balancers={sorted(used_bal)} skipped={dict(skipped)} -> {fname}")

    union_rules = []
    seen_rule = set()
    for els in vlist:
        rep = els[0]
        rules = (rep.get("routing", {}) or {}).get("rules", []) or []
        bal_groups_all = {}
        for bal, pref in BALANCER_PREFIX.items():
            members = names_for_outbounds(data, tag_prefix=pref)
            if members:
                bal_groups_all[bal] = bal
        cr, _, _ = translate_routing(rules, bal_groups_all, "SELECT")
        for r in cr:
            if r not in seen_rule:
                seen_rule.add(r)
                union_rules.append(r)
    variant_group_names = []
    for vi, els in enumerate(vlist, start=1):
        if variant_nodes(els):
            variant_group_names.append(f"V{vi:02d}")
    u_groups = [("AUTO", "url-test", [p["name"] for p in all_proxies]),
                ("SELECT", "select", ["AUTO", "DIRECT"] + variant_group_names)]
    for vi, els in enumerate(vlist, start=1):
        vnodes = variant_nodes(els)
        if not vnodes:
            continue
        u_groups.append((f"V{vi:02d}", "url-test", vnodes))
    for bal, pref in sorted(BALANCER_PREFIX.items()):
        members = names_for_outbounds(data, tag_prefix=pref)
        if members:
            u_groups.append((bal, "url-test", members))
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
        members = names_for_outbounds([el])
        if len(members) < 2:
            continue
        gname = rem
        if gname in reg.seen_names:
            gname = reg.reg_name(gname)
        else:
            reg.seen_names.add(gname)
        u_groups.append((gname, "url-test", members))
    dns_ns, dns_policy = translate_dns(common_dns)
    has_ru = any(r == "DOMAIN-SUFFIX,ru,DIRECT" for r in union_rules)
    has_geo = any(r.startswith("GEOIP,RU,DIRECT") for r in union_rules)
    header = [
        "# dobro-vpn.yaml — auto-generated FULL config from INCY JSON, do not edit manually",
        f"# source: dobro-incy.json (panel response to INCY UA) | routing variants: {len(vlist)}",
        "# All 15 variants are in this ONE file as groups V01..V15 (pick one in SELECT).",
        "# Rules are the UNION of all variants (one global rules list, first match wins).",
        "# For the exact per-variant routing, use the matching dobro-vpn-variant-XX.yaml.",
        "# Import as a Clash/Mihomo profile in Karing or Clash Verge Rev.",
    ]
    text = build_yaml(all_proxies, u_groups, dns_ns, dns_policy, union_rules, header)
    with open(os.path.join(out_dir, "dobro-vpn.yaml"), "w", encoding="utf-8") as f:
        f.write(text)
    print(f"unified dobro-vpn.yaml: proxies={len(all_proxies)} groups={len(u_groups)} "
          f"rules={len(union_rules)} .ru={has_ru} GEOIP-RU={has_geo} variants={len(vlist)}")
    print(f"variant files: {', '.join(variant_files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
