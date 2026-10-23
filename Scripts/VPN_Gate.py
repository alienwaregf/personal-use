#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Gate residential (home broadband) OpenVPN nodes -> mihomo proxy-provider file.

Standalone script, no verification by design (the user dropped the verify
stage after it wiped out the whole list from datacenter runners): nodes
are screened on the list only and liveness is left to the client's own
health checks, same division of labor as cfnew.

Screening (list-level only):
  1. Fetch the official VPN Gate CSV list (https first, http fallback).
  2. Drop the operator-run datacenter servers: HostName starting with
     "public-vpn", or IP inside 219.100.37.
  3. Sort the rest by the CSV Speed field, descending.
  4. Decode each OpenVPN config; keep only proto tcp entries with a remote.

Output is a provider file (top-level "proxies:") holding only the
residential OpenVPN nodes. Every node carries dialer-proxy pointing at
DIALER_PROXY_GROUP (the user's own auto-select group); no front nodes.
"""

import base64
import hashlib
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOURCE_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]
OUTPUT_PATH = Path("proxy/VPNgate.yaml")
DIALER_PROXY_GROUP = "自动选择"

EXCLUDE_HOST_PREFIX = "public-vpn"
EXCLUDE_IP_PREFIX = "219.100.37."
CONFIG_PREFIX_CHARS = 6000  # decode only the head of each config first
VERSION_TAG = "v3-noverify"

BEIJING = timezone(timedelta(hours=8))


def fetch_text(urls):
    last_error = None
    for url in urls:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Accept": "text/plain"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001 - try the next source
            last_error = e
    raise RuntimeError(f"节点源拉取失败：{last_error}")


def decode_config(config64, full=False):
    clean = re.sub(r"\s", "", config64)
    data = clean if full or len(clean) <= CONFIG_PREFIX_CHARS else clean[:CONFIG_PREFIX_CHARS]
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data).decode("utf-8", errors="replace")


_directive_cache = {}


def get_directive(text, name):
    if name not in _directive_cache:
        _directive_cache[name] = re.compile(
            r"^[ \t]*" + re.escape(name) + r"[ \t]+(.+?)[ \t]*$", re.M
        )
    m = _directive_cache[name].search(text)
    return m.group(1).strip() if m else ""


def get_inline_block(text, tag):
    m = re.search(r"<" + tag + r">([\s\S]*?)</" + tag + r">", text)
    return m.group(1).strip() if m else ""


def parse_list(raw):
    candidates = []
    excluded_official = 0
    for raw_line in raw.split("\n"):
        line = raw_line.strip()
        if not line or line[0] in "*#":
            continue
        fields = line.split(",")
        if len(fields) < 15:
            continue
        # Only residential: drop the operator-run datacenter servers.
        if (fields[0] or "").startswith(EXCLUDE_HOST_PREFIX) or (
            fields[1] or ""
        ).startswith(EXCLUDE_IP_PREFIX):
            excluded_official += 1
            continue
        config64 = fields[-1]
        if not config64 or len(config64) < 100:
            continue
        try:
            speed = int(fields[4])
        except (TypeError, ValueError):
            speed = 0
        candidates.append(
            {
                "country": (fields[6] or "").upper() or "XX",
                "speed": speed,
                "config64": config64,
            }
        )
    candidates.sort(key=lambda c: -c["speed"])

    nodes = []
    cert = None
    skipped_not_tcp = 0
    for item in candidates:
        try:
            text = decode_config(item["config64"])
            if not get_directive(text, "remote"):
                text = decode_config(item["config64"], full=True)
        except Exception:  # noqa: BLE001 - undecodable config, skip
            continue
        # The dialer chain can only carry TCP; UDP nodes are dropped.
        if (get_directive(text, "proto") or "tcp").lower() != "tcp":
            skipped_not_tcp += 1
            continue
        remote = get_directive(text, "remote").split()
        if not remote:
            continue
        if cert is None:
            # The client cert material is shared site-wide; take the first
            # complete set. Nodes before it are skipped.
            try:
                full_text = decode_config(item["config64"], full=True)
                found = {
                    "ca": get_inline_block(full_text, "ca"),
                    "cert": get_inline_block(full_text, "cert"),
                    "key": get_inline_block(full_text, "key"),
                }
                if found["ca"] and found["cert"] and found["key"]:
                    cert = found
            except Exception:  # noqa: BLE001
                pass
            if cert is None:
                continue
        try:
            port = int(remote[1])
        except (IndexError, TypeError, ValueError):
            port = 443
        nodes.append(
            {
                "country": item["country"],
                "server": remote[0],
                "port": port,
                "cipher": get_directive(text, "cipher") or "AES-128-CBC",
                "auth": get_directive(text, "auth") or "SHA1",
            }
        )
    stats = {
        "listed": len(candidates) + excluded_official,
        "excluded_official": excluded_official,
        "skipped_not_tcp": skipped_not_tcp,
    }
    return nodes, cert, stats


def indent_block(text, indent):
    return "\n".join(
        indent + line.strip() for line in text.split("\n") if line.strip()
    )


def render_yaml(nodes, cert, fingerprint):
    counters = {}
    named = []
    for node in nodes:
        counters[node["country"]] = counters.get(node["country"], 0) + 1
        named.append(
            (f"🏠 {node['country']}-家宽-{counters[node['country']]:02d}", node)
        )
    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# VPN Gate 家宽节点（OpenVPN）",
        "# 数据来源：VPN Gate 官方清单，已剔除 public-vpn 官方机房节点与 219.100.37. 网段",
        f"# 上次更新时间：{now}",
        f"# 条数：{len(named)} 个节点",
        f"# Hash：{fingerprint}",
        "proxies:",
    ]
    for idx, (name, node) in enumerate(named):
        lines += [
            f'  - name: "{name}"',
            "    type: openvpn",
            f"    server: {node['server']}",
            f"    port: {node['port']}",
            "    proto: tcp",
            "    username: vpn",
            "    password: vpn",
            f"    cipher: {node['cipher']}",
            f"    auth: {node['auth']}",
            "    udp: false",
            "    handshake-timeout: 30",
            "    remote-dns-resolve: true",
            "    dns: [ 8.8.8.8, 1.1.1.1 ]",
            f'    dialer-proxy: "{DIALER_PROXY_GROUP}"',
        ]
        # Shared cert: anchor on the first node, aliases afterwards.
        if idx == 0:
            lines.append("    ca: &jkca |-")
            lines.append(indent_block(cert["ca"], "      "))
            lines.append("    cert: &jkcert |-")
            lines.append(indent_block(cert["cert"], "      "))
            lines.append("    key: &jkkey |-")
            lines.append(indent_block(cert["key"], "      "))
        else:
            lines += ["    ca: *jkca", "    cert: *jkcert", "    key: *jkkey"]
    return "\n".join(lines) + "\n", len(named)


def stored_hash(path):
    if not path.exists():
        return ""
    head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    m = re.search(r"# Hash：([0-9a-f]{64})", head)
    return m.group(1) if m else ""


def main():
    raw = fetch_text(SOURCE_URLS)
    fingerprint = hashlib.sha256(
        raw.encode("utf-8")
        + Path(__file__).read_bytes()
        + VERSION_TAG.encode("utf-8")
    ).hexdigest()
    if stored_hash(OUTPUT_PATH) == fingerprint and OUTPUT_PATH.stat().st_size > 0:
        print("无更新，跳过：VPNgate")
        return 0
    nodes, cert, stats = parse_list(raw)
    if not nodes or not cert:
        # Never overwrite a good file with an empty one; fail loudly instead.
        print("解析不出可用节点，保留旧文件，退出", file=sys.stderr)
        return 1
    content, count = render_yaml(nodes, cert, fingerprint)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(content, encoding="utf-8")
    countries = {}
    for node in nodes:
        countries[node["country"]] = countries.get(node["country"], 0) + 1
    by_country = "、".join(
        f"{k} {v}" for k, v in sorted(countries.items(), key=lambda kv: -kv[1])
    )
    print(
        f"VPNgate 已更新：清单 {stats['listed']} 个，"
        f"剔除官方机房 {stats['excluded_official']} 个，"
        f"跳过非 TCP {stats['skipped_not_tcp']} 个，"
        f"生成家宽节点 {count} 个（{by_country}）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
