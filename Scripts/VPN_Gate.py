import base64
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SOURCE_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]
IP_API_BATCH = "http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,isp,org,as,hosting,proxy&lang=zh-CN"
OUTPUT_PATH = Path("proxy/VPNgate.yaml")

EXCLUDE_HOST_PREFIX = "public-vpn"
EXCLUDE_IP_PREFIX = "219.100.37."
CONFIG_PREFIX_CHARS = 6000  # decode only the head of each config first
VERSION_TAG = "v23-fail-visible"

BEIJING = timezone(timedelta(hours=8))


FETCH_DEADLINE = 120  # seconds, per attempt, for the whole download
FETCH_ATTEMPTS = 3

US_RETAIN_TTL = 720 * 60 * 60  # seconds: a US node that disappears from the list stays in the file this long past its last sighting


def fetch_once(url, deadline):
    """Download one URL under a total deadline.

    The per-read socket timeout alone cannot stop a slow-drip source
    (each gap stays under the timeout while the transfer never ends),
    so reads use read1 (one socket read per call, returning whatever
    has arrived) and the elapsed time is checked after every chunk.
    """
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0", "Accept": "text/plain"}
    )
    started = time.monotonic()
    chunks = []
    with urllib.request.urlopen(req, timeout=60) as resp:
        while True:
            chunk = resp.read1(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if time.monotonic() - started > deadline:
                raise TimeoutError(f"下载超过总时限 {deadline} 秒：{url}")
    return b"".join(chunks).decode("utf-8", errors="replace")


def fetch_text(urls):
    last_error = None
    for attempt in range(FETCH_ATTEMPTS):
        try:
            return fetch_once(urls[attempt % len(urls)], FETCH_DEADLINE)
        except Exception as e:  # noqa: BLE001 - retry on the next source
            last_error = e
            if attempt + 1 < FETCH_ATTEMPTS:
                time.sleep(5)
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
                "country_long": (fields[5] or "").strip(),
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
                "country_long": item["country_long"],
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
    """Drop nodes whose server IP is flagged hosting/datacenter, or whose
    ip-api country disagrees with the CSV country code. The second rule
    catches cloud-fronted IPs (e.g. a Cloudflare WARP egress): the CSV
    code follows the IP block's registration while ip-api follows the
    anycast PoP, so the two sources point at different countries. The
    ip-api proxy flag is deliberately NOT used here: it fires on plain
    residential ISPs too (44 of 75 nodes in one real run, including
    SoftBank/KDDI/SK Broadband lines)."""
    info = classify_ips([n["server_ip"] for n in nodes if n["server_ip"]])
    if not info:
        return nodes, {"ran": False, "dropped_hosting": 0, "dropped_mismatch": 0}
    kept, dropped_hosting, dropped_mismatch = [], 0, 0
    for node in nodes:
        entry = info.get(node["server_ip"])
        if entry and entry.get("hosting"):
            dropped_hosting += 1
            continue
        csv_code = node["country"]
        if (
            entry
            and entry.get("countryCode")
            and csv_code not in ("", "XX")
            and entry["countryCode"] != csv_code
        ):
            dropped_mismatch += 1
            continue
        if entry:
            node["isp"] = entry.get("isp", "")
            node["asn"] = entry.get("as", "")
            node["country_name"] = (entry.get("country") or "").strip()
            node["region"] = (entry.get("regionName") or "").strip()
            node["city"] = (entry.get("city") or "").strip()
        kept.append(node)
    return kept, {
        "ran": True,
        "dropped_hosting": dropped_hosting,
        "dropped_mismatch": dropped_mismatch,
    }


def inline_pem(text):
    """PEM block as a one-line double-quoted YAML string (\\n escapes)."""
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    return '"' + "\\n".join(lines) + '"'


COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "VN": "越南", "TH": "泰国",
    "RU": "俄罗斯", "LA": "老挝", "NL": "荷兰", "FR": "法国", "TW": "台湾",
    "HK": "香港", "SG": "新加坡", "GB": "英国", "DE": "德国", "CA": "加拿大",
    "AU": "澳大利亚", "IN": "印度", "ID": "印尼", "MY": "马来西亚", "PH": "菲律宾",
    "CN": "中国", "IT": "意大利", "ES": "西班牙", "BR": "巴西", "MX": "墨西哥",
    "TR": "土耳其", "UA": "乌克兰", "PL": "波兰", "SE": "瑞典", "CH": "瑞士",
}


def flag_emoji(code):
    if len(code) == 2 and code.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 0x41) for c in code.upper())
    return ""


def display_name(node):
    country = (
        node.get("country_name")
        or COUNTRY_ZH.get(node["country"])
        or node.get("country_long")
        or node["country"]
    )
    city = (node.get("city") or "").strip() or (node.get("region") or "").strip()
    if city == country:
        city = ""
    flag = flag_emoji(node["country"])
    head = f"{country} {city} 家宽" if city else f"{country} 家宽"
    if flag:
        head = f"{flag} {head}"
    return f"{head} {node['server']}"


def render_yaml(nodes, cert, fingerprint, us_seen=None):
    totals = {}
    for node in nodes:
        totals[display_name(node)] = totals.get(display_name(node), 0) + 1
    seen = {}
    named = []
    for node in nodes:
        base = display_name(node)
        seen[base] = seen.get(base, 0) + 1
        count = seen[base]
        if totals[base] == 1:
            name = base
        else:
            head, ip = base.split(" 家宽 ", 1)
            name = head + str(count).translate(str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")) + " 家宽 " + ip
        named.append((base, count, name, node))
    named.sort(key=lambda item: (item[0], item[1]))
    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# VPN Gate 家宽节点（OpenVPN）",
        "# 数据来源：VPN Gate 官方清单，已剔除 public-vpn 官方机房节点、219.100.37. 网段及 IP 情报标记为机房的 IP",
        f"# 上次更新时间：{now}",
        f"# 条数：{len(named)} 个节点",
        f"# Hash：{fingerprint}",
    ]
    if us_seen:
        for server, port in sorted(us_seen):
            seen_at = us_seen[(server, port)].astimezone(BEIJING)
            lines.append(
                f"# US seen {server}:{port} {seen_at.strftime('%Y-%m-%dT%H:%M:%S+08:00')}"
            )
    lines += [
        "x-certs:",
        "  ca: &jkca " + inline_pem(cert["ca"]),
        "  cert: &jkcert " + inline_pem(cert["cert"]),
        "  key: &jkkey " + inline_pem(cert["key"]),
        "proxies:",
    ]
    for _, _, name, node in named:
        # One node per line (flow style); every node only carries aliases.
        # A single quote inside a single-quoted name must be doubled,
        # otherwise it ends the string early and breaks the flow mapping.
        safe_name = name.replace("'", "''")
        lines.append(
            "  - { "
            f"name: '{safe_name}', type: openvpn, server: {node['server']}, "
            f"port: {node['port']}, proto: tcp, username: vpn, password: vpn, "
            f"cipher: {node['cipher']}, auth: {node['auth']}, "
            "ca: *jkca, cert: *jkcert, key: *jkkey"
            " }"
        )
    return "\n".join(lines) + "\n", len(named)


def stored_hash(path):
    if not path.exists():
        return ""
    head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    m = re.search(r"# Hash：([0-9a-f]{64})", head)
    return m.group(1) if m else ""


def stored_time(path):
    """Beijing timestamp from the output file header, or None if absent/unparseable."""
    if not path.exists():
        return None
    head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    m = re.search(r"# 上次更新时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", head)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=BEIJING)
    except ValueError:
        return None


SUPERSCRIPT_CHARS = "⁰¹²³⁴⁵⁶⁷⁸⁹"


def flag_to_code(flag):
    if len(flag) == 2 and all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in flag):
        return "".join(chr(ord(c) - 0x1F1E6 + 0x41) for c in flag)
    return ""


def node_from_old_proxy(proxy):
    """Rebuild a pipeline node dict from a parsed old-file US proxy.

    The old display name already carries everything display_name needs:
    flag, Chinese country, city (maybe with a duplicate superscript) and
    server. The superscript is stripped here; the pipeline recomputes
    suffixes for the merged set, so numbering stays contiguous.
    Returns None when the old name does not follow our format.
    """
    name = proxy.get("name") or ""
    server = proxy.get("server") or ""
    if not name or not server or " 家宽 " not in name:
        return None
    code = flag_to_code(name[:2])
    if not code:
        return None
    head = name[2:].strip().split(" 家宽 ", 1)[0]
    geo = head.rstrip(SUPERSCRIPT_CHARS)
    parts = geo.split(" ", 1)
    country_name = parts[0]
    city = parts[1] if len(parts) > 1 else ""
    try:
        port = int(proxy.get("port", 443))
    except (TypeError, ValueError):
        port = 443
    return {
        "country": code,
        "country_name": country_name,
        "city": city,
        "region": "",
        "server": server,
        "server_ip": server,
        "port": port,
        "cipher": proxy.get("cipher") or "AES-128-CBC",
        "auth": proxy.get("auth") or "SHA1",
    }


def load_retention(path):
    """Read the previous file's US nodes and their last-seen times.

    Returns (old_us, seen, file_time): old_us maps (server, port) to a
    rebuilt pipeline node dict, seen maps (server, port) to the datetime
    it was last seen upstream, file_time is the header timestamp (or
    None). The old node lines are parsed with a regex for our fixed
    field order, so this needs no YAML library. Missing, unreadable or
    unparseable files yield empty results; the caller then simply has
    nothing to retain.
    """
    old_us = {}
    seen = {}
    file_time = stored_time(path)
    if not path.exists():
        return old_us, seen, file_time
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return old_us, seen, file_time
    for line in text.split("\n"):
        m = re.match(r"# US seen (\S+):(\d+) (\S+)", line)
        if m:
            try:
                seen[(m.group(1), int(m.group(2)))] = datetime.fromisoformat(m.group(3))
            except ValueError:
                continue
    for line in text.split("\n"):
        if "name: '🇺🇸" not in line:
            continue
        m = re.search(
            r"name: '(.*)', type: openvpn, server: (\S+), port: (\d+), "
            r"proto: tcp, username: vpn, password: vpn, cipher: (\S+), auth: (\S+),",
            line,
        )
        if not m:
            continue
        node = node_from_old_proxy(
            {
                "name": m.group(1).replace("''", "'"),
                "server": m.group(2),
                "port": int(m.group(3)),
                "cipher": m.group(4),
                "auth": m.group(5),
            }
        )
        if node:
            old_us[(node["server"], node["port"])] = node
    return old_us, seen, file_time


def merge_retained(fresh, path, now):
    """Merge disappeared US nodes from the previous file into this run.

    Returns (merged_nodes, us_seen). Fresh nodes always win on
    (server, port); a disappeared US node is kept only while its last
    sighting is within US_RETAIN_TTL. A node with no recorded sighting
    falls back to the previous file's header time, then to now.
    Seen times for fresh US nodes are now; retained ones keep their old
    sighting time, so the 30-day clock keeps running from when they
    were last actually upstream.
    """
    old_us, old_seen, file_time = load_retention(path)
    fresh_keys = {(n["server"], n["port"]) for n in fresh}
    retained = []
    for key, node in old_us.items():
        if key in fresh_keys:
            continue
        last = old_seen.get(key) or file_time or now
        if (now - last).total_seconds() < US_RETAIN_TTL:
            retained.append(node)
    merged = list(fresh) + retained
    us_seen = {}
    for n in merged:
        if n["country"] == "US":
            key = (n["server"], n["port"])
            if key in old_us and key not in fresh_keys:
                us_seen[key] = old_seen.get(key) or file_time or now
            else:
                us_seen[key] = now
    return merged, us_seen


def main():
    try:
        raw = fetch_text(SOURCE_URLS)
    except Exception as e:
        if OUTPUT_PATH.exists():
            print(f"拉取失败（{e}），上版所有节点不动、保留旧文件，退出", file=sys.stderr)
            return 1
        raise
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
    merged, us_seen = merge_retained(nodes, OUTPUT_PATH, datetime.now(BEIJING))
    content, count = render_yaml(merged, cert, fingerprint, us_seen)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(content, encoding="utf-8")
    countries = {}
    for node in merged:
        countries[node["country"]] = countries.get(node["country"], 0) + 1
    by_country = "、".join(
        f"{k} {v}" for k, v in sorted(countries.items(), key=lambda kv: -kv[1])
    )
    ip_text = (
        f"IP 情报剔除机房 {ip_stats['dropped_hosting']} 个、"
        f"国家不一致 {ip_stats['dropped_mismatch']} 个"
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
