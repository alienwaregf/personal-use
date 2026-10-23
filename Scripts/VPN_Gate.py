#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Gate residential (home broadband) OpenVPN nodes -> mihomo proxy-provider file.

Standalone script. The goal is genuinely residential exits, so unlike cfnew
(which only filters the list), this script verifies:

  Stage A (list screening, cfnew's sound rules kept):
    fetch the official VPN Gate CSV; drop the operator-run datacenter
    servers (HostName "public-vpn*" or IP in 219.100.37.); decode each
    OpenVPN config; keep only proto tcp entries with a remote.
  Stage B (IP intelligence):
    batch-classify every candidate server IP via ip-api; drop IPs flagged
    as hosting/datacenter.
  Stage C (active verification, the part cfnew does not do):
    actually open each surviving tunnel with OpenVPN, read the real exit
    IP through the tunnel, classify that exit IP, and drop the node if the
    exit is hosting/datacenter or the tunnel never comes up. Nodes are
    ranked by the measured through-tunnel latency, not by VPN Gate's
    claimed Speed field (which is only used to order the probing).

If OpenVPN / a tun device / root is unavailable, Stage C degrades to a TCP
reachability check and the output header says so; the full check runs in
GitHub Actions (the workflow installs openvpn).

Output: a provider file (top-level "proxies:") with only verified
residential OpenVPN nodes. Every node carries dialer-proxy pointing at
DIALER_PROXY_GROUP (the user's own auto-select group); no front nodes.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOURCE_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]
IP_API_BATCH = "http://ip-api.com/batch?fields=status,query,isp,org,as,hosting,proxy"
EGRESS_URL = "http://ip-api.com/json/?fields=status,query,country,isp,org,as,hosting,proxy"
OUTPUT_PATH = Path("proxy/VPNgate.yaml")
DIALER_PROXY_GROUP = "自动选择"

EXCLUDE_HOST_PREFIX = "public-vpn"
EXCLUDE_IP_PREFIX = "219.100.37."
CONFIG_PREFIX_CHARS = 6000  # cfnew decodes only the head of each config first

PROBE_WORKERS = 4
CONNECT_TIMEOUT_S = 20
EGRESS_TIMEOUT_S = 15
VERIFY_VERSION = "v2-egress"

BEIJING = timezone(timedelta(hours=8))


# ---------------------------------------------------------------- sources

def fetch_text(urls):
    last_error = None
    for url in urls:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0", "Accept": "text/plain"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001 - try the next source, like cfnew
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


# ------------------------------------------------------- stage A: screening

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
    # Claimed speed only orders the probing queue now; final ranking is
    # measured in stage C.
    candidates.sort(key=lambda c: -c["speed"])

    nodes = []
    cert = None
    skipped_not_tcp = 0
    for item in candidates:
        try:
            text = decode_config(item["config64"])
            if not get_directive(text, "remote"):
                text = decode_config(item["config64"], full=True)
        except Exception:  # noqa: BLE001 - undecodable config, skip like cfnew
            continue
        # The dialer chain can only carry TCP; UDP nodes are dropped.
        if (get_directive(text, "proto") or "tcp").lower() != "tcp":
            skipped_not_tcp += 1
            continue
        remote = get_directive(text, "remote").split()
        if not remote:
            continue
        try:
            full_text = decode_config(item["config64"], full=True)
        except Exception:  # noqa: BLE001
            continue
        if cert is None:
            found = {
                "ca": get_inline_block(full_text, "ca"),
                "cert": get_inline_block(full_text, "cert"),
                "key": get_inline_block(full_text, "key"),
            }
            if found["ca"] and found["cert"] and found["key"]:
                cert = found
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
                "config_text": full_text,
            }
        )
    stats = {
        "listed": len(candidates) + excluded_official,
        "excluded_official": excluded_official,
        "skipped_not_tcp": skipped_not_tcp,
        "after_a": len(nodes),
    }
    return nodes, cert, stats


# -------------------------------------------- stage B: IP intelligence

def classify_ips(ips):
    """Return {ip: ip-api dict}; empty dict when the service is unusable."""
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
        except Exception:  # noqa: BLE001 - stage B is a pre-filter, not fatal
            return {}
    return result


def stage_b(nodes):
    info = classify_ips([n["server_ip"] for n in nodes if n["server_ip"]])
    if not info:
        return nodes, {"b_checked": 0, "b_dropped_hosting": 0, "b_ran": False}
    kept, dropped = [], 0
    for node in nodes:
        entry = info.get(node["server_ip"])
        if entry and entry.get("hosting"):
            dropped += 1
            continue
        node["server_isp"] = (entry or {}).get("isp", "")
        kept.append(node)
    return kept, {"b_checked": len(info), "b_dropped_hosting": dropped, "b_ran": True}


# -------------------------------------------- stage C: active verification

def probe_environment():
    """Return (full_mode: bool, sudo_prefix: list)."""
    if not shutil.which("openvpn") or not Path("/dev/net/tun").exists():
        return False, []
    if os.geteuid() == 0:
        return True, []
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=10
        )
        if r.returncode == 0:
            return True, ["sudo", "-n"]
    except Exception:  # noqa: BLE001
        pass
    return False, []


_STRIP_LINE = re.compile(
    r"^[ \t]*(dev|dev-type|redirect-gateway|redirect-private|route|route-ipv6|"
    r"dhcp-option|auth-user-pass|management|up|down|ipchange|route-up|"
    r"script-security|connect-retry|connect-retry-max|connect-timeout|"
    r"server-poll-timeout|explicit-exit-notify|tun-mtu|tun-mtu-extra|"
    r"mssfix|fragment)\b",
    re.M,
)


def build_probe_config(node, slot, workdir):
    text = _STRIP_LINE.sub("# stripped:", node["config_text"])
    # Keep only the first remote line; extra remotes would slow failure.
    remotes = list(re.finditer(r"^[ \t]*remote[ \t]+.+$", text, re.M))
    if len(remotes) > 1:
        parts, last = [], 0
        for m in remotes[1:]:
            parts.append(text[last : m.start()])
            last = m.end()
        parts.append(text[last:])
        text = "".join(parts)
    auth_file = workdir / "auth.txt"
    auth_file.write_text("vpn\nvpn\n", encoding="utf-8")
    extra = (
        f"\ndev tun{slot}\ndev-type tun\nroute-nopull\nnobind\n"
        f"auth-user-pass {auth_file}\nauth-nocache\n"
        f"connect-timeout {CONNECT_TIMEOUT_S}\nconnect-retry-max 1\n"
        "resolv-retry 2\nverb 3\n"
    )
    cfg = workdir / "probe.ovpn"
    cfg.write_text(text + extra, encoding="utf-8")
    return cfg


def probe_node(node, slot, sudo):
    """Open the tunnel, read the real exit IP through it, classify it."""
    workdir = Path(tempfile.mkdtemp(prefix=f"vgprobe{slot}_"))
    pid_file = workdir / "openvpn.pid"
    log_file = workdir / "openvpn.log"
    proc_hint = None
    try:
        cfg = build_probe_config(node, slot, workdir)
        cmd = sudo + [
            "openvpn", "--config", str(cfg), "--daemon",
            "--log", str(log_file), "--writepid", str(pid_file),
            "--cd", str(workdir),
        ]
        subprocess.run(cmd, capture_output=True, timeout=30)
        deadline = time.monotonic() + CONNECT_TIMEOUT_S + 10
        up = False
        while time.monotonic() < deadline:
            log_text = (
                log_file.read_text(encoding="utf-8", errors="replace")
                if log_file.exists()
                else ""
            )
            if "Initialization Sequence Completed" in log_text:
                up = True
                break
            # Fail fast: many nodes reset the connection and the daemon
            # exits within seconds; do not burn the whole timeout on them.
            if (
                "Exiting due to fatal error" in log_text
                or "AUTH_FAILED" in log_text
                or "Cannot open TUN/TAP dev" in log_text
            ):
                break
            if pid_file.exists():
                try:
                    daemon_pid = int(pid_file.read_text().strip())
                    os.kill(daemon_pid, 0)
                except ProcessLookupError:
                    break
                except PermissionError:
                    pass  # owned by root via sudo; cannot signal-check it
                except (ValueError, OSError):
                    pass
            time.sleep(0.5)
        if not up:
            return node, "connect_failed"
        url = EGRESS_URL
        # route-nopull leaves no route into the tunnel, so pin host routes
        # for the egress-check IPs via this slot's tun device; otherwise
        # the check would silently leave through the default gateway.
        egress_host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        try:
            egress_ips = socket.gethostbyname_ex(egress_host)[2]
        except OSError:
            egress_ips = [egress_host]
        for ip in egress_ips:
            subprocess.run(
                sudo + ["ip", "route", "add", f"{ip}/32", "dev", f"tun{slot}"],
                capture_output=True, timeout=10,
            )
        node["_egress_ips"] = egress_ips
        node["_slot"] = slot
        start = time.monotonic()
        r = subprocess.run(
            sudo
            + [
                "curl", "-s", "--noproxy", "*", "--interface", f"tun{slot}",
                "--max-time", str(EGRESS_TIMEOUT_S), url,
            ],
            capture_output=True, timeout=EGRESS_TIMEOUT_S + 15,
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        try:
            info = json.loads(r.stdout.decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            return node, "no_egress"
        if info.get("status") != "success" or not info.get("query"):
            return node, "no_egress"
        if info.get("hosting"):
            return node, "egress_hosting"
        node["egress_ip"] = info["query"]
        node["egress_isp"] = info.get("isp", "")
        node["latency_ms"] = latency_ms
        return node, "ok"
    except Exception:  # noqa: BLE001 - any probe error drops the node
        return node, "probe_error"
    finally:
        for ip in node.pop("_egress_ips", []):
            try:
                subprocess.run(
                    sudo
                    + ["ip", "route", "del", f"{ip}/32", "dev", f"tun{node.get('_slot', slot)}"],
                    capture_output=True, timeout=10,
                )
            except Exception:  # noqa: BLE001
                pass
        node.pop("_slot", None)
        try:
            if pid_file.exists():
                pid = int(pid_file.read_text().strip())
                killer = sudo + ["kill", str(pid)]
                subprocess.run(killer, capture_output=True, timeout=10)
                proc_hint = pid
                time.sleep(0.3)
                subprocess.run(
                    sudo + ["kill", "-9", str(pid)], capture_output=True, timeout=10
                )
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(workdir, ignore_errors=True)


def tcp_reachable(node):
    try:
        with socket.create_connection((node["server"], node["port"]), timeout=5):
            return True
    except OSError:
        return False


def stage_c(nodes, full_mode, sudo):
    reasons = {}
    if not full_mode:
        kept = []
        for node in nodes:
            if tcp_reachable(node):
                node["latency_ms"] = None
                kept.append(node)
            else:
                reasons["tcp_unreachable"] = reasons.get("tcp_unreachable", 0) + 1
        return kept, reasons
    results = []
    # Slots are leased from a pool: two live probes never share a tun device.
    import queue

    slot_pool = queue.Queue()
    for slot in range(PROBE_WORKERS):
        slot_pool.put(slot)

    def run_with_slot(node):
        slot = slot_pool.get()
        try:
            return probe_node(node, slot, sudo)
        finally:
            slot_pool.put(slot)

    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        futures = [pool.submit(run_with_slot, node) for node in nodes]
        for fut in futures:
            node, status = fut.result()
            if status == "ok":
                results.append(node)
            else:
                reasons[status] = reasons.get(status, 0) + 1
    results.sort(key=lambda n: n["latency_ms"])
    return results, reasons


# ------------------------------------------------------------------- output

def indent_block(text, indent):
    return "\n".join(
        indent + line.strip() for line in text.split("\n") if line.strip()
    )


def render_yaml(nodes, cert, fingerprint, full_mode):
    counters = {}
    named = []
    for node in nodes:
        counters[node["country"]] = counters.get(node["country"], 0) + 1
        named.append(
            (f"🏠 {node['country']}-家宽-{counters[node['country']]:02d}", node)
        )
    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S")
    if full_mode:
        verify_line = "# 验证：逐个实连 OpenVPN 验出口 IP（机房出口已剔除），按实测延迟排序"
    else:
        verify_line = "# 验证：IP 情报剔除机房 + 端口连通（本环境无 OpenVPN 条件，未验出口）"
    lines = [
        "# VPN Gate 家宽节点（OpenVPN）",
        "# 数据来源：VPN Gate 官方清单，已剔除 public-vpn 官方机房节点与 219.100.37. 网段",
        verify_line,
        f"# 上次更新时间：{now}",
        f"# 条数：{len(named)} 个节点",
        f"# Hash：{fingerprint}",
        "proxies:",
    ]
    for idx, (name, node) in enumerate(named):
        if full_mode:
            lines.append(
                f"  # 出口 {node['egress_ip']} · {node['egress_isp']} · 实测 {node['latency_ms']}ms"
            )
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
    full_mode, sudo = probe_environment()
    mode = "full" if full_mode else "degraded"
    raw = fetch_text(SOURCE_URLS)
    fingerprint = hashlib.sha256(
        raw.encode("utf-8")
        + Path(__file__).read_bytes()
        + f"{VERIFY_VERSION}:{mode}".encode("utf-8")
    ).hexdigest()
    if stored_hash(OUTPUT_PATH) == fingerprint and OUTPUT_PATH.stat().st_size > 0:
        print("无更新，跳过：VPNgate")
        return 0

    nodes, cert, stats = parse_list(raw)
    if not nodes or not cert:
        print("清单解析不出可用节点，保留旧文件，退出", file=sys.stderr)
        return 1
    nodes, b_stats = stage_b(nodes)
    nodes, c_reasons = stage_c(nodes, full_mode, sudo)
    if not nodes:
        print("验证后无可用节点，保留旧文件，退出", file=sys.stderr)
        return 1

    content, count = render_yaml(nodes, cert, fingerprint, full_mode)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(content, encoding="utf-8")

    countries = {}
    for node in nodes:
        countries[node["country"]] = countries.get(node["country"], 0) + 1
    by_country = "、".join(
        f"{k} {v}" for k, v in sorted(countries.items(), key=lambda kv: -kv[1])
    )
    reason_text = "、".join(f"{k} {v}" for k, v in sorted(c_reasons.items())) or "无"
    b_text = (
        f"IP 情报剔除机房 {b_stats['b_dropped_hosting']} 个"
        if b_stats["b_ran"]
        else "IP 情报不可用（跳过 B 阶段）"
    )
    print(
        f"VPNgate 已更新（{mode} 模式）：清单 {stats['listed']} 个，"
        f"剔除官方机房 {stats['excluded_official']} 个，"
        f"跳过非 TCP {stats['skipped_not_tcp']} 个，{b_text}，"
        f"实连验证淘汰 {sum(c_reasons.values())} 个（{reason_text}），"
        f"最终家宽节点 {count} 个（{by_country}）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())