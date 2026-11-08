#!/usr/bin/env python3
"""Fetch the FixNet (FixCord) Happ subscription with Happ headers,
drop the Happ-only metadata, and write a plain list of proxy
share-links usable in any client (Clash Verge, Karing, ...).

Server names are kept exactly as returned (including the
'?serverDescription=...' tail) — no name cleaning, so nothing
can be accidentally cut off.

Env:
  FIXNET_SUB_URL  full subscription URL (GitHub Secret)
  FIXNET_HWID     device HWID (GitHub Secret)
  FIXNET_UA       User-Agent, default "Happ/4.8.0"
  FIXNET_OUT      output file, default "fixnet-sub.txt"
"""
import os
import sys
from urllib.request import Request, urlopen

SUB_URL = os.environ.get("FIXNET_SUB_URL", "").strip()
HWID = os.environ.get("FIXNET_HWID", "").strip()
UA = os.environ.get("FIXNET_UA", "Happ/4.8.0").strip()
OUT = os.environ.get("FIXNET_OUT", "fixnet-sub.txt")

LINK_PREFIXES = (
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria2://", "hysteria://", "tuic://", "socks://",
)


def main() -> int:
    if not SUB_URL:
        print("FIXNET_SUB_URL is not set", file=sys.stderr)
        return 2
    if not HWID:
        print("FIXNET_HWID is not set", file=sys.stderr)
        return 2
    req = Request(SUB_URL, headers={
        "User-Agent": UA,
        "X-HWID": HWID,
        "Accept": "*/*",
    })
    with urlopen(req, timeout=30) as resp:
        if resp.status != 200:
            print(f"subscription fetch failed: HTTP {resp.status}",
                  file=sys.stderr)
            return 1
        text = resp.read().decode("utf-8", errors="replace")
    out_lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue  # Happ metadata, not a proxy link
        if line.startswith("happ://"):
            continue  # Happ-specific (routing), not a proxy link
        if line.startswith(LINK_PREFIXES):
            out_lines.append(line)
        # anything else is ignored
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out_lines))
        if out_lines:
            f.write("\n")
    print(f"wrote {len(out_lines)} links to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
