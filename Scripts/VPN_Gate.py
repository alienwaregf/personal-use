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
VERSION_TAG = "v18-us-36h-top-anchors"

BEIJING = timezone(timedelta(hours=8))


FETCH_DEADLINE = 120  # seconds, per attempt, for the whole download
FETCH_ATTEMPTS = 3

FETCH_FALLBACK_TTL = 10 * 60  # seconds: on fetch failure, keep the committed file and exit 0 while it is this fresh
US_FALLBACK_TTL = 720 * 60 * 60  # seconds: past the tier above, keep only US nodes and exit 0 while the file is this fresh


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


def render_yaml(nodes, cert, fingerprint):
    seen = {}
    named = []
    for node in nodes:
        base = display_name(node)
        seen[base] = seen.get(base, 0) + 1
        name = base if seen[base] == 1 else f"{base}-{seen[base]:02d}"
        named.append((name, node))
    named.sort(key=lambda item: item[0])
    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# VPN Gate 家宽节点（OpenVPN）",
        "# 数据来源：VPN Gate 官方清单，已剔除 public-vpn 官方机房节点、219.100.37. 网段及 IP 情报标记为机房的 IP",
        f"# 上次更新时间：{now}",
        f"# 条数：{len(named)} 个节点",
        f"# Hash：{fingerprint}",
        # The shared cert lives once in its own block above the nodes, so
        # no node line is long and dropping nodes never orphans an anchor.
        "x-certs:",
        "  ca: &jkca " + inline_pem(cert["ca"]),
        "  cert: &jkcert " + inline_pem(cert["cert"]),
        "  key: &jkkey " + inline_pem(cert["key"]),
        "proxies:",
    ]
    for name, node in named:
        # One node per line (flow style); every node only carries aliases.
        lines.append(
            "  - { "
            f"name: '{name}', type: openvpn, server: {node['server']}, "
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


def rewrite_us_only(path):
    """Rewrite the committed file keeping only US nodes.

    The header time is deliberately NOT refreshed: it still marks when the
    kept nodes were last fully updated, so the 36h bound keeps counting down
    instead of renewing on every rewrite. The Hash line is dropped so the
    unchanged-skip logic can never mistake this partial file for a full one.
    The cert anchors live in the standalone x-certs block above the nodes,
    which is kept as-is, so filtering node lines cannot orphan an alias.
    Returns True on success, False when there is nothing safe to write.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")
    try:
        pidx = lines.index("proxies:")
    except ValueError:
        return False
    header = lines[:pidx]
    body = [line for line in lines[pidx + 1:] if line.strip()]
    us = [line for line in body if "name: '🇺🇸" in line]
    if not us:
        return False
    kept = [line for line in header
            if not line.startswith("# 条数") and not line.startswith("# Hash")]
    count_line = f"# 条数：{len(us)} 个节点（仅美国，分层回退）"
    for i, line in enumerate(kept):
        if line.startswith("# 上次更新时间"):
            kept.insert(i + 1, count_line)
            break
    else:
        kept.append(count_line)
    path.write_text("\n".join(kept + ["proxies:"] + us) + "\n", encoding="utf-8")
    return True


def main():
    try:
        raw = fetch_text(SOURCE_URLS)
    except Exception as e:
        stored = stored_time(OUTPUT_PATH)
        age = (datetime.now(BEIJING) - stored).total_seconds() if stored else None
        if age is not None and age < FETCH_FALLBACK_TTL:
            print(f"拉取失败（{e}），但现有文件 {age:.0f} 秒前才更新（TTL 内），保留旧文件")
            return 0
        if age is not None and age < US_FALLBACK_TTL:
            if rewrite_us_only(OUTPUT_PATH):
                print(f"拉取失败（{e}），现有文件 {age:.0f} 秒前更新（超 10 分钟、未超 36 小时），仅保留美国节点")
                return 0
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
