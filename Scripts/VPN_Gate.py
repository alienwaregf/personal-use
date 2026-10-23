#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Gate residential (home broadband) OpenVPN nodes -> mihomo proxy-provider file.

Standalone script. Screening is list/IP based only; there is NO
connectivity checking anywhere (no tunnel is ever opened) - liveness is
left to the client's own health checks.

Screening:
  1. Fetch the official VPN Gate CSV list (https first, http fallback).
  2. Drop the operator-run datacenter servers: HostName starting with
     "public-vpn", or IP inside 219.100.37.
  3. Classify every remaining server IP via ip-api and drop the ones
     flagged as hosting/datacenter, so volunteers running on a VPS do
     not pass as residential. (Screening IPs, not testing connections.)
  4. Sort by the CSV Speed field, descending.
  5. Decode each OpenVPN config; keep only proto tcp entries with a remote.

Output is a provider file (top-level "proxies:") holding only the
residential OpenVPN nodes. Every node carries dialer-proxy pointing at
DIALER_PROXY_GROUP (the user's own auto-select group); no front nodes.
"""

import base64
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOURCE_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]
IP_API_BATCH = "http://ip-api.com/batch?fields=status,query,regionName,city,isp,org,as,hosting,proxy&lang=zh-CN"
OUTPUT_PATH = Path("proxy/VPNgate.yaml")
DIALER_PROXY_GROUP = "自动选择"

EXCLUDE_HOST_PREFIX = "public-vpn"
EXCLUDE_IP_PREFIX = "219.100.37."
CONFIG_PREFIX_CHARS = 6000  # decode only the head of each config first
VERSION_TAG = "v7-oneline"

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
                "server_ip": (fields[1] or "").strip(),
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
                "server_ip": item["server_ip"],
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


def classify_ips(ips):
    """Batch-classify IPs via ip-api; empty dict when the service is down."""
    result = {}
    unique = sorted(set(ips))
    for i in range(0, len(unique), 100):
        batch = unique[i : i + 100]
        try:
            req = urllib.request.Request(
                IP_API_BATCH,
                data=json.dumps(batch).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                for entry in json.loads(resp.read().decode("utf-8")):
                    if entry.get("status") == "success":
                        result[entry["query"]] = entry
        except Exception:  # noqa: BLE001 - screening aid, not fatal
            return {}
    return result


def screen_datacenter_ips(nodes):
    """Drop nodes whose server IP is flagged hosting/datacenter."""
    info = classify_ips([n["server_ip"] for n in nodes if n["server_ip"]])
    if not info:
        return nodes, {"ran": False, "dropped": 0}
    kept, dropped = [], 0
    for node in nodes:
        entry = info.get(node["server_ip"])
        if entry and entry.get("hosting"):
            dropped += 1
            continue
        if entry:
            node["isp"] = entry.get("isp", "")
            node["asn"] = entry.get("as", "")
            parts = []
            for part in (entry.get("regionName", ""), entry.get("city", "")):
                part = (part or "").strip()
                if part and part not in parts:
                    parts.append(part)
            node["place"] = " ".join(parts)
        kept.append(node)
    return kept, {"ran": True, "dropped": dropped}


def inline_pem(text):
    """PEM block as a one-line double-quoted YAML string (\\n escapes)."""
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    return '"' + "\\n".join(lines) + '"'


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
        "# 数据来源：VPN Gate 官方清单，已剔除 public-vpn 官方机房节点、219.100.37. 网段及 IP 情报标记为机房的 IP",
        f"# 上次更新时间：{now}",
        f"# 条数：{len(named)} 个节点",
        f"# Hash：{fingerprint}",
        "proxies:",
    ]
    for idx, (name, node) in enumerate(named):
        if node.get("isp"):
            comment = f"  # {node['isp']} · {node.get('asn', '')}"
            if node.get("place"):
                comment = f"  # {node['place']} · {node['isp']} · {node.get('asn', '')}"
            lines.append(comment)
        # One node per line (flow style); the shared cert is anchored on
        # the first node and aliased by all the others, on the same line.
        if idx == 0:
            cert_fields = (
                "ca: &jkca " + inline_pem(cert["ca"])
                + ", cert: &jkcert " + inline_pem(cert["cert"])
                + ", key: &jkkey " + inline_pem(cert["key"])
            )
        else:
            cert_fields = "ca: *jkca, cert: *jkcert, key: *jkkey"
        lines.append(
            "  - {"
            f'name: "{name}", type: openvpn, server: {node["server"]}, '
            f"port: {node['port']}, proto: tcp, username: vpn, password: vpn, "
            f"cipher: {node['cipher']}, auth: {node['auth']}, udp: false, "
            "handshake-timeout: 30, remote-dns-resolve: true, "
            "dns: [8.8.8.8, 1.1.1.1], "
            f'dialer-proxy: "{DIALER_PROXY_GROUP}", {cert_fields}'
            "}"
        )
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
    nodes, ip_stats = screen_datacenter_ips(nodes)
    if not nodes:
        print("机房 IP 筛选后无可用节点，保留旧文件，退出", file=sys.stderr)
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
    ip_text = (
        f"IP 情报剔除机房 {ip_stats['dropped']} 个"
        if ip_stats["ran"]
        else "IP 情报不可用（本轮未筛机房 IP）"
    )
    print(
        f"VPNgate 已更新：清单 {stats['listed']} 个，"
        f"剔除官方机房 {stats['excluded_official']} 个，"
        f"跳过非 TCP {stats['skipped_not_tcp']} 个，{ip_text}，"
        f"生成家宽节点 {count} 个（{by_country}）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
