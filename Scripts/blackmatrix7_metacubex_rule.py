"""blackmatrix7 x MetaCubeX merged rule converter.

For each name in UPSTREAM_INCLUDE_FOLDERS, fetches the blackmatrix7
Classical rules and the MetaCubeX geosite/geoip rules of the same name,
unions them, and writes a merged rule/<Name>/ folder (classical yaml,
.mrs files, four client .list files, README). Standalone script;
both upstreams are fetched file-by-file, nothing else is pulled.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
from datetime import datetime, timedelta, timezone
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml


BLACK_RAW_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "blackmatrix7/ios_rule_script/master/rule/Clash"
)
META_RAW_BASE_URL = (
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo"
)

MY_REPO_URL = "https://github.com/alienwaregf/personal-use"
MY_RAW_RULE_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "alienwaregf/personal-use/main/rule"
)

DEST_RULE_DIR = Path("rule")
TEMP_DIR = Path("temp_compile")

HTTP_USER_AGENT = "personal-use-rule-converter"
HTTP_TIMEOUT = 60

CLIENTS = ["Clash", "Loon", "QuantumultX", "Shadowrocket", "Surge"]
NON_CLASH_CLIENTS = [client for client in CLIENTS if client != "Clash"]
CLIENT_LIST_FILES = {client: f"{client}.list" for client in NON_CLASH_CLIENTS}

UPSTREAM_INCLUDE_FOLDERS = {
    "Advertising",
    "AppStore",
    "Apple",
    "AppleFirmware",
    "AppleHardware",
    "AppleID",
    "AppleMail",
    "AppleMedia",
    "AppleMusic",
    "AppleNews",
    "AppleProxy",
    "AppleTV",
    "Binance",
    "Bing",
    "category-ads-all",
    "category-ai-!cn",
    "ChinaMax",
    "Claude",
    "Cloudflare",
    "Copilot",
    "Discord",
    "Disney",
    "Docker",
    "Download",
    "DMM",
    "EA",
    "Epic",
    "Facebook",
    "FindMy",
    "FitnessPlus",
    "Gemini",
    "GitHub",
    "Google",
    "GoogleEarth",
    "GoogleFCM",
    "HBO",
    "Instagram",
    "iCloud",
    "iCloudPrivateRelay",
    "IPTVMainland",
    "IPTVOther",
    "Lan",
    "Line",
    "Mail",
    "Microsoft",
    "Netflix",
    "Nvidia",
    "NTPService",
    "Oracle",
    "OpenAI",
    "PayPal",
    "PikPak",
    "PlayStation",
    "PrivateTracker",
    "Reddit",
    "Riot",
    "Siri",
    "Spotify",
    "Steam",
    "Telegram",
    "TestFlight",
    "Threads",
    "TikTok",
    "Tmdb",
    "Twitch",
    "Twitter",
    "Vercel",
    "Whatsapp",
    "Wikipedia",
    "Xbox",
    "YouTube",
}

META_ALIASES: Dict[str, str] = {
    "Advertising": "category-ads-all",
    "AppleMusic": "apple-music",
    "AppleTV": "apple-tvplus",
    "ChinaMax": "cn",
    "Claude": "anthropic",
    "Copilot": "github-copilot",
    "Epic": "epicgames",
    "Gemini": "google-gemini",
    "Lan": "private",
}


CLIENT_TYPE_MAP: Dict[str, Dict[str, Optional[str]]] = {
    "DOMAIN": {
        "Clash": "DOMAIN",
        "Loon": "DOMAIN",
        "QuantumultX": "HOST",
        "Shadowrocket": "DOMAIN",
        "Surge": "DOMAIN",
    },
    "DOMAIN-SUFFIX": {
        "Clash": "DOMAIN-SUFFIX",
        "Loon": "DOMAIN-SUFFIX",
        "QuantumultX": "HOST-SUFFIX",
        "Shadowrocket": "DOMAIN-SUFFIX",
        "Surge": "DOMAIN-SUFFIX",
    },
    "DOMAIN-KEYWORD": {
        "Clash": "DOMAIN-KEYWORD",
        "Loon": "DOMAIN-KEYWORD",
        "QuantumultX": "HOST-KEYWORD",
        "Shadowrocket": "DOMAIN-KEYWORD",
        "Surge": "DOMAIN-KEYWORD",
    },
    "DOMAIN-WILDCARD": {
        "Clash": "DOMAIN-WILDCARD",
        "Loon": "DOMAIN-WILDCARD",
        "QuantumultX": None,
        "Shadowrocket": None,
        "Surge": "DOMAIN-WILDCARD",
    },
    "IP-CIDR": {
        "Clash": "IP-CIDR",
        "Loon": "IP-CIDR",
        "QuantumultX": "IP-CIDR",
        "Shadowrocket": "IP-CIDR",
        "Surge": "IP-CIDR",
    },
    "IP-CIDR6": {
        "Clash": "IP-CIDR6",
        "Loon": "IP-CIDR6",
        "QuantumultX": "IP6-CIDR",
        "Shadowrocket": "IP-CIDR6",
        "Surge": "IP-CIDR6",
    },
    "IP-ASN": {
        "Clash": "IP-ASN",
        "Loon": None,
        "QuantumultX": None,
        "Shadowrocket": "IP-ASN",
        "Surge": "IP-ASN",
    },
    "SRC-IP-CIDR": {
        "Clash": "SRC-IP-CIDR",
        "Loon": None,
        "QuantumultX": None,
        "Shadowrocket": "SRC-IP-CIDR",
        "Surge": "SRC-IP",
    },
    "GEOIP": {
        "Clash": "GEOIP",
        "Loon": "GEOIP",
        "QuantumultX": "GEOIP",
        "Shadowrocket": "GEOIP",
        "Surge": "GEOIP",
    },
    "DST-PORT": {
        "Clash": "DST-PORT",
        "Loon": None,
        "QuantumultX": None,
        "Shadowrocket": None,
        "Surge": "DEST-PORT",
    },
    "SRC-PORT": {
        "Clash": "SRC-PORT",
        "Loon": None,
        "QuantumultX": None,
        "Shadowrocket": None,
        "Surge": "SRC-PORT",
    },
    "PROCESS-NAME": {
        "Clash": "PROCESS-NAME",
        "Loon": None,
        "QuantumultX": None,
        "Shadowrocket": None,
        "Surge": "PROCESS-NAME",
    },
    "PROCESS-PATH": {
        "Clash": "PROCESS-PATH",
        "Loon": None,
        "QuantumultX": None,
        "Shadowrocket": None,
        "Surge": None,
    },
    "URL-REGEX": {
        "Clash": "URL-REGEX",
        "Loon": "URL-REGEX",
        "QuantumultX": None,
        "Shadowrocket": None,
        "Surge": "URL-REGEX",
    },
    "USER-AGENT": {
        "Clash": "USER-AGENT",
        "Loon": "USER-AGENT",
        "QuantumultX": "USER-AGENT",
        "Shadowrocket": "USER-AGENT",
        "Surge": "USER-AGENT",
    },
    "AND": {"Clash": "AND", "Loon": None, "QuantumultX": None,
            "Shadowrocket": None, "Surge": None},
    "OR": {"Clash": "OR", "Loon": None, "QuantumultX": None,
           "Shadowrocket": None, "Surge": None},
    "NOT": {"Clash": "NOT", "Loon": None, "QuantumultX": None,
            "Shadowrocket": None, "Surge": None},
    "RULE-SET": {"Clash": "RULE-SET", "Loon": None, "QuantumultX": None,
                 "Shadowrocket": None, "Surge": None},
    "SUB-RULE": {"Clash": "SUB-RULE", "Loon": None, "QuantumultX": None,
                 "Shadowrocket": None, "Surge": None},
}

MRS_DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
MRS_SKIP_DOMAIN_TYPES = {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}

SUPPORTED_OUTPUT_TYPES = set(CLIENT_TYPE_MAP)

NO_RESOLVE_SUFFIX = "no-resolve"

RuleParts = List[str]


def quote_path_part(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def strip_yaml_quote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_payload_rule_line(line: str) -> Optional[RuleParts]:
    line = strip_yaml_quote(line.strip())
    if not line or line.startswith("#"):
        return None
    try:
        parsed = next(csv.reader(io.StringIO(line), skipinitialspace=True))
    except csv.Error:
        return None
    parts = [part.strip() for part in parsed if part.strip()]
    if len(parts) < 2:
        return None
    parts[0] = parts[0].upper()
    return parts


def parse_rule_items(items: Iterable[str]) -> List[RuleParts]:
    parsed_rules: List[RuleParts] = []
    for line in items:
        parts = parse_payload_rule_line(line)
        if parts is not None:
            parsed_rules.append(parts)
    return parsed_rules


def ensure_mihomo_exists() -> None:
    if shutil.which("mihomo") is None:
        raise RuntimeError(
            "未找到 mihomo 可执行文件, 请先安装并加入 PATH")


def write_mrs_source_yaml(path: Path, entries: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        output_file.write("payload:\n")
        for rule in entries:
            dumped = yaml.safe_dump(
                rule, allow_unicode=True, default_flow_style=True).strip()
            output_file.write("  - " + dumped + "\n")


def compile_to_mrs(source_yaml: Path, target_mrs: Path, behavior: str) -> None:
    target_mrs.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "mihomo", "convert-ruleset", behavior, "yaml",
        str(source_yaml), str(target_mrs),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"mihomo 转换失败 ({behavior}): {source_yaml} -> {target_mrs}\n"
            f"{result.stdout}\n{result.stderr}".strip()
        )
    if not target_mrs.exists() or target_mrs.stat().st_size <= 0:
        raise RuntimeError(f"mihomo 未生成有效 .mrs 文件: {target_mrs}")


def split_mrs_rules(
    rules: Iterable[RuleParts],
) -> Tuple[List[str], List[str]]:
    domain_entries: List[str] = []
    ip_entries: List[str] = []
    skipped_counts: Dict[str, int] = {}

    for parts in rules:
        kind, value = parts[0], parts[1]
        if kind in MRS_DOMAIN_TYPES:
            if kind == "DOMAIN":
                domain_entries.append("+." + value)
            else:
                domain_entries.append("+." + value)
        elif kind in MRS_SKIP_DOMAIN_TYPES:
            skipped_counts[kind] = skipped_counts.get(kind, 0) + 1
        elif kind in ("IP-CIDR", "IP-CIDR6"):
            ip_entries.append(value)

    for skipped_type, count in sorted(skipped_counts.items()):
        print(f"跳过 {count} 条 .mrs 不支持的规则类型：{skipped_type}")
    return list(dict.fromkeys(domain_entries)), list(dict.fromkeys(ip_entries))


def compile_rules_to_mrs(dest_folder: Path, folder_name: str,
                         domain_entries: Sequence[str],
                         ip_entries: Sequence[str]) -> List[str]:
    temp_folder = TEMP_DIR / folder_name
    generated_files: List[str] = []

    domain_yaml = temp_folder / f"{folder_name}_domain.yaml"
    domain_mrs = dest_folder / f"{folder_name}.mrs"
    if domain_entries:
        write_mrs_source_yaml(domain_yaml, domain_entries)
        compile_to_mrs(domain_yaml, domain_mrs, "domain")
        generated_files.append(f"{folder_name}.mrs")
    else:
        domain_mrs.unlink(missing_ok=True)

    ip_yaml = temp_folder / f"{folder_name}_ip.yaml"
    ip_mrs = dest_folder / f"{folder_name}_IP.mrs"
    if ip_entries:
        write_mrs_source_yaml(ip_yaml, ip_entries)
        compile_to_mrs(ip_yaml, ip_mrs, "ipcidr")
        generated_files.append(f"{folder_name}_IP.mrs")
    else:
        ip_mrs.unlink(missing_ok=True)

    return generated_files


def fetch_optional_text(url: str) -> Optional[str]:
    request = urllib.request.Request(
        url, headers={"User-Agent": HTTP_USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError(f"抓取失败 HTTP {error.code}: {url}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"抓取失败: {url}: {error}") from error


def parse_payload_text(text: str) -> List[str]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as error:
        raise RuntimeError(f"MetaCubeX YAML 解析失败: {error}") from error
    payload = data.get("payload", []) if isinstance(data, dict) else []
    return [str(item) for item in payload if str(item).strip()]


def parse_meta_geosite(text: str) -> Tuple[List[RuleParts], int]:
    rules: List[RuleParts] = []
    skipped = 0
    for entry in parse_payload_text(text):
        entry = entry.strip()
        if entry.startswith("+."):
            value = entry[2:].strip().lower()
            if value:
                rules.append(["DOMAIN-SUFFIX", value])
                continue
        elif re.fullmatch(r"[a-z0-9.\-]+", entry.lower()):
            rules.append(["DOMAIN", entry.lower()])
            continue
        skipped += 1
    return rules, skipped


def parse_meta_geoip(text: str) -> Tuple[List[RuleParts], int]:
    rules: List[RuleParts] = []
    skipped = 0
    for entry in parse_payload_text(text):
        entry = entry.strip()
        try:
            network = ipaddress.ip_network(entry)
        except ValueError:
            skipped += 1
            continue
        kind = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
        rules.append([kind, str(network)])
    return rules, skipped


def meta_stem_for(folder_name: str) -> str:
    return META_ALIASES.get(folder_name, folder_name.lower())


def load_meta_rules(
    folder_name: str,
) -> Tuple[List[RuleParts], Dict[str, int], str, str]:
    stem = meta_stem_for(folder_name)
    encoded = quote_path_part(stem)
    stats: Dict[str, int] = {"geosite": 0, "geoip": 0, "skipped": 0}
    rules: List[RuleParts] = []

    geosite_text = fetch_optional_text(
        f"{META_RAW_BASE_URL}/geosite/{encoded}.yaml")
    if geosite_text is not None:
        site_rules, site_skipped = parse_meta_geosite(geosite_text)
        stats["geosite"] = len(site_rules)
        stats["skipped"] += site_skipped
        rules.extend(site_rules)

    geoip_text = fetch_optional_text(
        f"{META_RAW_BASE_URL}/geoip/{encoded}.yaml")
    if geoip_text is not None:
        ip_rules, ip_skipped = parse_meta_geoip(geoip_text)
        stats["geoip"] = len(ip_rules)
        stats["skipped"] += ip_skipped
        rules.extend(ip_rules)

    return rules, stats, geosite_text or "", geoip_text or ""


def dedup_key(parts: Sequence[str]) -> Tuple[str, ...]:
    kind = parts[0].upper()
    if kind in ("IP-CIDR", "IP-CIDR6"):
        return (kind, parts[1])
    return tuple(part.upper() if index == 0 else part
                 for index, part in enumerate(parts))


def merge_rule_sets(
    black_rules: Sequence[RuleParts],
    meta_rules: Sequence[RuleParts],
) -> Tuple[List[RuleParts], int]:
    seen: Set[Tuple[str, ...]] = set()
    merged: List[RuleParts] = []
    for parts in black_rules:
        key = dedup_key(parts)
        if key not in seen:
            seen.add(key)
            merged.append(list(parts))
    added = 0
    for parts in meta_rules:
        key = dedup_key(parts)
        if key not in seen:
            seen.add(key)
            merged.append(list(parts))
            added += 1
    return merged, added


def prune_covered_domain_rules(
    rules: Sequence[RuleParts],
) -> Tuple[List[RuleParts], int]:
    suffixes = {
        parts[1]
        for parts in rules
        if len(parts) >= 2 and parts[0].upper() == "DOMAIN-SUFFIX"
    }
    if not suffixes:
        return [list(parts) for parts in rules], 0

    def has_suffix_ancestor(value: str, include_self: bool) -> bool:
        labels = value.split(".")
        start = 0 if include_self else 1
        return any(
            ".".join(labels[i:]) in suffixes
            for i in range(start, len(labels))
        )

    kept: List[RuleParts] = []
    removed = 0
    for parts in rules:
        kind = parts[0].upper() if parts else ""
        covered = len(parts) >= 2 and (
            (kind == "DOMAIN" and has_suffix_ancestor(parts[1], True))
            or (kind == "DOMAIN-SUFFIX"
                and has_suffix_ancestor(parts[1], False))
        )
        if covered:
            removed += 1
        else:
            kept.append(list(parts))
    return kept, removed


def build_client_rule_line(parts: Sequence[str], client: str) -> str:
    if len(parts) < 2:
        raise ValueError("规则至少包含类型和值两段")
    source_type = parts[0].upper()
    value = parts[1]
    extras = [part for part in parts[2:]]
    type_map = CLIENT_TYPE_MAP.get(source_type)
    if type_map is None:
        return ""
    target_type = type_map.get(client)
    if target_type is None:
        return ""
    if extras not in ([], [NO_RESOLVE_SUFFIX]):
        raise ValueError(
            f"{client} 不支持规则参数 {extras}: {','.join(parts)}")

    if source_type == "IP-CIDR6" and "/" not in value and ":" in value:
        value += "/128"
    if client == "Loon" and source_type == "IP-CIDR" and "/" not in value:
        value += "/32"
    if client == "QuantumultX":
        if source_type == "IP-CIDR" and "/" not in value:
            value += "/32"
        elif source_type == "IP-CIDR6" and "/" not in value:
            value += "/128"
    if client == "Surge" and source_type == "IP-CIDR6" and "/" not in value:
        value += "/128"

    output_parts = [target_type, value]
    if NO_RESOLVE_SUFFIX in extras:
        output_parts.append(NO_RESOLVE_SUFFIX)
    if client == "Loon" and target_type in {"IP-CIDR", "IP-CIDR6"}:
        output_parts = [target_type, value + ",extended-matching"]
    return ",".join(output_parts)


def build_client_list(rules: Sequence[RuleParts],
                      client: str) -> List[str]:
    lines: List[str] = []
    skipped_by_type: Dict[str, int] = {}
    failed_by_type: Dict[str, int] = {}
    for parts in rules:
        source_type = parts[0].upper() if parts else ""
        try:
            line = build_client_rule_line(parts, client)
        except ValueError:
            failed_by_type[source_type] = \
                failed_by_type.get(source_type, 0) + 1
            continue
        if line:
            lines.append(line)
        else:
            skipped_by_type[source_type] = \
                skipped_by_type.get(source_type, 0) + 1
    for skipped_type, count in sorted(skipped_by_type.items()):
        print(f"跳过 {count} 条 {client} 不支持的规则类型：{skipped_type}")
    for failed_type, count in sorted(failed_by_type.items()):
        print(f"跳过 {count} 条 {client} 无法安全表达的规则：{failed_type}")
    return lines


def write_client_lists(dest_folder: Path,
                       rules: Sequence[RuleParts]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for client in NON_CLASH_CLIENTS:
        lines = build_client_list(rules, client)
        counts[client] = len(lines)
        output_path = dest_folder / CLIENT_LIST_FILES[client]
        output_path.write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return counts


def yaml_scalar_text(value: str) -> str:
    dumped = yaml.safe_dump(
        value, allow_unicode=True, default_flow_style=True).strip()
    lines = dumped.split("\n")
    if lines and lines[-1] == "...":
        lines.pop()
    return "\n".join(lines).strip()


BEIJING_TZ = timezone(timedelta(hours=8))


def write_classical_yaml(dest_folder: Path, folder_name: str,
                         rules: Sequence[RuleParts],
                         black_source: Optional[str],
                         black_count: int,
                         meta_stats: Dict[str, int],
                         merged_count: int, pruned_count: int,
                         fingerprint: str) -> None:
    meta_count = meta_stats["geosite"] + meta_stats["geoip"]
    sources: List[str] = []
    if black_source:
        sources.append("blackmatrix7")
    if meta_count:
        sources.append("MetaCubeX")
    updated = datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")
    count_line = (
        f"# 条数：blackmatrix7 {black_count} 条 + MetaCubeX {meta_count} 条 "
        f"(geosite {meta_stats['geosite']} / geoip {meta_stats['geoip']}) "
        f"→ 去重合并 {merged_count + pruned_count} 条"
    )
    if pruned_count:
        count_line += f"，去冗 {pruned_count} 条，实存 {merged_count} 条"
    header = [
        f"# 数据来源：{' + '.join(sources)}",
        f"# 上次更新时间：{updated}",
        count_line,
        f"# Hash：{fingerprint}",
    ]

    output_path = dest_folder / f"{folder_name}.yaml"
    with output_path.open("w", encoding="utf-8") as output_file:
        output_file.write("\n".join(header) + "\n")
        output_file.write("payload:\n")
        for parts in rules:
            output_file.write("  - " + yaml_scalar_text(",".join(parts)) + "\n")


CLIENT_ICONS = {
    "Clash": (
        "https://raw.githubusercontent.com/"
        "alienwaregf/personal-use/refs/heads/main/"
        "Picture/icon/OpenClash.png"
    ),
    "Loon": (
        "https://raw.githubusercontent.com/"
        "lige47/QuanX-icon-rule/main/"
        "icon/02ProxySoftLogo/Loon(1).png"
    ),
    "QuantumultX": (
        "https://raw.githubusercontent.com/"
        "alienwaregf/personal-use/refs/heads/main/"
        "Picture/icon/QX.png"
    ),
    "Shadowrocket": (
        "https://raw.githubusercontent.com/"
        "alienwaregf/personal-use/refs/heads/main/"
        "Picture/icon/shadowrocket.png"
    ),
    "Surge": (
        "https://raw.githubusercontent.com/"
        "lige47/QuanX-icon-rule/main/"
        "icon/02ProxySoftLogo/Surge(8).png"
    ),
}


def client_heading(client: str) -> str:
    icon = CLIENT_ICONS[client]
    return (
        f'# <img src="{icon}" '
        f'width="25" height="25" '
        f'alt="{client}" /> {client}\n\n'
    )


def build_client_section(
    client: str,
    folder_name: str,
    classical_filename: str,
    has_domain_mrs: bool,
    has_ip_mrs: bool,
) -> str:
    folder_url = quote_path_part(folder_name)
    parts: List[str] = [client_heading(client)]

    if client == "Clash":
        if has_domain_mrs:
            parts.append(
                "domain\n"
                "```text\n"
                f"{MY_RAW_RULE_BASE_URL}/"
                f"{folder_url}/"
                f"{quote_path_part(folder_name + '.mrs')}\n"
                "```\n\n"
            )
        if has_ip_mrs:
            parts.append(
                "ipcidr\n"
                "```text\n"
                f"{MY_RAW_RULE_BASE_URL}/"
                f"{folder_url}/"
                f"{quote_path_part(folder_name + '_IP.mrs')}\n"
                "```\n\n"
            )
        parts.append(
            "classical\n"
            "```text\n"
            f"{MY_RAW_RULE_BASE_URL}/"
            f"{folder_url}/"
            f"{quote_path_part(classical_filename)}\n"
            "```\n\n"
        )
        return "".join(parts)

    filename = CLIENT_LIST_FILES[client]
    parts.append(
        "```text\n"
        f"{MY_RAW_RULE_BASE_URL}/"
        f"{folder_url}/"
        f"{quote_path_part(filename)}\n"
        "```\n\n"
    )
    return "".join(parts)


def client_section_text(
    folder_name: str,
    classical_filename: str,
    has_domain_mrs: bool,
    has_ip_mrs: bool,
) -> str:
    sections: List[str] = []
    for client in CLIENTS:
        sections.append(
            build_client_section(
                client=client,
                folder_name=folder_name,
                classical_filename=classical_filename,
                has_domain_mrs=has_domain_mrs,
                has_ip_mrs=has_ip_mrs,
            ).rstrip()
        )
    return "\n\n".join(sections)


def write_readme(dest_folder: Path, folder_name: str,
                 generated_mrs_files: Sequence[str]) -> None:
    text = client_section_text(
        folder_name=folder_name,
        classical_filename=f"{folder_name}.yaml",
        has_domain_mrs=f"{folder_name}.mrs" in generated_mrs_files,
        has_ip_mrs=f"{folder_name}_IP.mrs" in generated_mrs_files,
    )
    (dest_folder / "README.md").write_text(
        text.rstrip() + "\n", encoding="utf-8")


BLACK_FILE_CANDIDATES = ("{name}_Classical.yaml", "{name}.yaml",
                         "{name}_Classical.yml", "{name}.yml")


def load_black_rules(
    folder_name: str,
) -> Tuple[List[RuleParts], Optional[str], str]:
    encoded_folder = quote_path_part(folder_name)
    for pattern in BLACK_FILE_CANDIDATES:
        filename = pattern.format(name=folder_name)
        text = fetch_optional_text(
            f"{BLACK_RAW_BASE_URL}/{encoded_folder}/"
            f"{quote_path_part(filename)}")
        if text is not None:
            return parse_rule_items(parse_payload_text(text)), filename, text
    return [], None, ""


_MIHOMO_VERSION: Optional[str] = None
_SCRIPT_BYTES: Optional[bytes] = None


def get_mihomo_version() -> str:
    global _MIHOMO_VERSION
    if _MIHOMO_VERSION is None:
        result = subprocess.run(["mihomo", "-v"],
                                capture_output=True, text=True)
        lines = (result.stdout + result.stderr).strip().splitlines()
        _MIHOMO_VERSION = lines[0].strip() if lines else ""
    return _MIHOMO_VERSION


def compute_fingerprint(black_text: str, geosite_text: str,
                        geoip_text: str) -> str:
    global _SCRIPT_BYTES
    if _SCRIPT_BYTES is None:
        _SCRIPT_BYTES = Path(__file__).read_bytes()
    digest = hashlib.sha256()
    for text in (black_text, geosite_text, geoip_text):
        digest.update(text.encode("utf-8"))
        digest.update(b"\n")
    digest.update(_SCRIPT_BYTES)
    digest.update(b"\n")
    digest.update(get_mihomo_version().encode("utf-8"))
    return digest.hexdigest()


HASH_LINE_RE = re.compile(r"^# Hash：([0-9a-f]{64})\s*$", re.MULTILINE)


def read_stored_hash(yaml_path: Path) -> Optional[str]:
    try:
        head = yaml_path.read_text(encoding="utf-8")[:2048]
    except OSError:
        return None
    match = HASH_LINE_RE.search(head)
    return match.group(1) if match else None


def outputs_complete(dest_folder: Path, folder_name: str,
                     merged: Sequence[RuleParts]) -> bool:
    required = [dest_folder / f"{folder_name}.yaml",
                dest_folder / "README.md"]
    required += [dest_folder / CLIENT_LIST_FILES[client]
                 for client in NON_CLASH_CLIENTS]
    if any(parts[0] in MRS_DOMAIN_TYPES for parts in merged):
        required.append(dest_folder / f"{folder_name}.mrs")
    if any(parts[0] in ("IP-CIDR", "IP-CIDR6") for parts in merged):
        required.append(dest_folder / f"{folder_name}_IP.mrs")
    return all(path.is_file() and path.stat().st_size > 0
               for path in required)


def process_folder(folder_name: str) -> Optional[Dict[str, int]]:
    black_rules, black_source, black_text = load_black_rules(folder_name)
    meta_rules, meta_stats, geosite_text, geoip_text = \
        load_meta_rules(folder_name)
    if not black_rules and not meta_rules:
        print(f"跳过不存在的规则目录: {folder_name} (两边上游都没有)")
        return None

    merged, meta_added = merge_rule_sets(black_rules, meta_rules)
    merged, pruned_count = prune_covered_domain_rules(merged)
    if pruned_count:
        print(f"去冗余：{folder_name} 移除 {pruned_count} 条"
              f"已被 DOMAIN-SUFFIX 覆盖的规则", flush=True)
    merged = sorted(merged)
    dest_folder = DEST_RULE_DIR / folder_name
    fingerprint = compute_fingerprint(black_text, geosite_text, geoip_text)
    yaml_path = dest_folder / f"{folder_name}.yaml"
    if read_stored_hash(yaml_path) == fingerprint and \
            outputs_complete(dest_folder, folder_name, merged):
        print(f"跳过未变化的上游目录: {folder_name}", flush=True)
        return {
            "black": len(black_rules),
            "meta": meta_stats["geosite"] + meta_stats["geoip"],
            "meta_added": meta_added,
            "merged": len(merged),
            "pruned": pruned_count,
            "meta_skipped": meta_stats["skipped"],
            "skipped": 1,
        }

    dest_folder.mkdir(parents=True, exist_ok=True)
    write_classical_yaml(dest_folder, folder_name, merged, black_source,
                         len(black_rules), meta_stats, len(merged),
                         pruned_count, fingerprint)

    domain_entries, ip_entries = split_mrs_rules(merged)
    generated_mrs = compile_rules_to_mrs(dest_folder, folder_name,
                                         domain_entries, ip_entries)
    write_client_lists(dest_folder, merged)
    write_readme(dest_folder, folder_name, generated_mrs)

    print(f"上游规则转换完成: {folder_name}", flush=True)
    return {
        "black": len(black_rules),
        "meta": meta_stats["geosite"] + meta_stats["geoip"],
        "meta_added": meta_added,
        "merged": len(merged),
        "pruned": pruned_count,
        "meta_skipped": meta_stats["skipped"],
        "skipped": 0,
    }


def main() -> None:
    if not UPSTREAM_INCLUDE_FOLDERS:
        print("名单是空的: 先在 UPSTREAM_INCLUDE_FOLDERS 里写要融合的"
              "规则名, 再运行")
        return
    ensure_mihomo_exists()
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    total_added = 0
    total_pruned = 0
    done = 0
    skipped = 0
    try:
        for folder_name in sorted(UPSTREAM_INCLUDE_FOLDERS):
            result = process_folder(folder_name)
            if result is not None:
                done += 1
                skipped += result.get("skipped", 0)
                if not result.get("skipped"):
                    total_added += result["meta_added"]
                    total_pruned += result.get("pruned", 0)
    finally:
        if TEMP_DIR.exists():
            shutil.rmtree(TEMP_DIR)
    summary = (f"全部完成: 共处理 {done} 个规则目录 (跳过未变化 {skipped} 个), "
               f"MetaCubeX 共补入 {total_added} 条黑矩阵没有的规则")
    if total_pruned:
        summary += f", 共去冗 {total_pruned} 条"
    print(summary)


if __name__ == "__main__":
    main()
