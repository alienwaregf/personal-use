# -*- coding: utf-8 -*-
"""blackmatrix7 x MetaCubeX merged rule converter.

For each name in UPSTREAM_INCLUDE_FOLDERS, fetches the blackmatrix7
Classical rules and the MetaCubeX geosite/geoip rules of the same name,
unions them, and writes a merged rule/<Name>/ folder (classical yaml,
.mrs files, four client .list files, README). Standalone script;
both upstreams are fetched file-by-file, nothing else is pulled.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

# =============================================================================
# Core Configuration
# =============================================================================

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
    "alienwaregf/personal-use/refs/heads/main/rule"
)

DEST_RULE_DIR = Path("rule")
TEMP_DIR = Path("temp_compile")

HTTP_USER_AGENT = "personal-use-rule-converter"
HTTP_TIMEOUT = 60

CLIENTS = ["Clash", "Loon", "QuantumultX", "Shadowrocket", "Surge"]
NON_CLASH_CLIENTS = [client for client in CLIENTS if client != "Clash"]
CLIENT_LIST_FILES = {client: f"{client}.list" for client in NON_CLASH_CLIENTS}

# UPSTREAM_INCLUDE_FOLDERS = {
#     "OpenAI",
#     "Netflix",
#     "category-ai-!cn",
# }
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
    "AppleMusic": "apple-music",
    "Claude": "anthropic",
    "Epic": "epicgames",
    "Gemini": "google-gemini",
}

# =============================================================================
# Type Mapping
# =============================================================================


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

# =============================================================================
# Core Parsing Utilities
# =============================================================================


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



# =============================================================================
# Mihomo Compilation
# =============================================================================


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
            else:  # DOMAIN-SUFFIX
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


# =============================================================================
# MetaCubeX Fetching and Parsing
# =============================================================================


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


def load_meta_rules(folder_name: str) -> Tuple[List[RuleParts], Dict[str, int]]:
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

    return rules, stats


# =============================================================================
# Merge
# =============================================================================


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



# =============================================================================
# Client List Generation
# =============================================================================


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


# =============================================================================
# Merge
# =============================================================================


def yaml_scalar_text(value: str) -> str:
    dumped = yaml.safe_dump(
        value, allow_unicode=True, default_flow_style=True).strip()
    lines = dumped.split("\n")
    if lines and lines[-1] == "...":
        lines.pop()
    return "\n".join(lines).strip()


def write_classical_yaml(dest_folder: Path, folder_name: str,
                         rules: Sequence[RuleParts],
                         black_source: Optional[str],
                         black_count: int,
                         meta_stats: Dict[str, int],
                         merged_count: int, meta_added: int) -> None:
    stem = meta_stem_for(folder_name)
    encoded = quote_path_part(stem)
    header = [
        f"# {folder_name} 融合规则 (blackmatrix7 × MetaCubeX)",
        "# 由 Scripts/blackmatrix7_metacubex_rule.py 自动生成, 请勿手动修改",
        "# 数据来源:",
    ]
    if black_source:
        header.append(
            "#   - blackmatrix7: "
            "https://raw.githubusercontent.com/blackmatrix7/"
            f"ios_rule_script/master/rule/Clash/{folder_name}/{black_source}")
    else:
        header.append("#   - blackmatrix7: (无此规则)")
    if meta_stats["geosite"]:
        header.append(
            "#   - MetaCubeX geosite: "
            f"{META_RAW_BASE_URL}/geosite/{encoded}.yaml")
    if meta_stats["geoip"]:
        header.append(
            "#   - MetaCubeX geoip: "
            f"{META_RAW_BASE_URL}/geoip/{encoded}.yaml")
    if not meta_stats["geosite"] and not meta_stats["geoip"]:
        header.append("#   - MetaCubeX: (无同名规则)")
    header.append(
        f"# 条数: 黑矩阵 {black_count} 条 + MetaCubeX "
        f"{meta_stats['geosite'] + meta_stats['geoip']} 条"
        f" (geosite {meta_stats['geosite']} / geoip {meta_stats['geoip']})"
        f" → 去重合并 {merged_count} 条 (其中 Meta 新增 {meta_added} 条)")

    output_path = dest_folder / f"{folder_name}.yaml"
    with output_path.open("w", encoding="utf-8") as output_file:
        output_file.write("\n".join(header) + "\n")
        output_file.write("payload:\n")
        for parts in rules:
            output_file.write("  - " + yaml_scalar_text(",".join(parts)) + "\n")


# =============================================================================
# README Generation
# =============================================================================


def folder_base_url(folder_name: str) -> str:
    return f"{MY_RAW_RULE_BASE_URL}/{quote_path_part(folder_name)}"


def write_readme(dest_folder: Path, folder_name: str,
                 classical_count: int, domain_mrs_count: int,
                 ip_mrs_count: int,
                 client_counts: Dict[str, int],
                 generated_mrs_files: Sequence[str]) -> None:
    base_url = folder_base_url(folder_name)
    lines: List[str] = [f"## {folder_name} (blackmatrix7 × MetaCubeX 融合)", ""]

    lines.append("### Clash")
    lines.append("")
    lines.append(
        f"当前融合规则已收录条数: [{classical_count}]"
        f"({base_url}/{folder_name}.yaml)")
    lines.append("")
    lines.append("```ini")
    lines.append(f"{base_url}/{folder_name}.yaml")
    lines.append("```")
    lines.append("")
    if f"{folder_name}.mrs" in generated_mrs_files:
        lines.append(
            f"当前 Domain .mrs 已收录条数: [{domain_mrs_count}]"
            f"({base_url}/{folder_name}.mrs)")
        lines.append("")
        lines.append("```ini")
        lines.append(f"{base_url}/{folder_name}.mrs")
        lines.append("```")
        lines.append("")
    if f"{folder_name}_IP.mrs" in generated_mrs_files:
        lines.append(
            f"当前 IP .mrs 已收录条数: [{ip_mrs_count}]"
            f"({base_url}/{folder_name}_IP.mrs)")
        lines.append("")
        lines.append("```ini")
        lines.append(f"{base_url}/{folder_name}_IP.mrs")
        lines.append("```")
        lines.append("")

    for client in NON_CLASH_CLIENTS:
        lines.append(f"### {client}")
        lines.append("")
        lines.append(
            f"当前规则已收录条数: [{client_counts.get(client, 0)}]"
            f"({base_url}/{CLIENT_LIST_FILES[client]})")
        lines.append("")
        lines.append("```ini")
        lines.append(f"{base_url}/{CLIENT_LIST_FILES[client]}")
        lines.append("```")
        lines.append("")

    (dest_folder / "README.md").write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8")



# =============================================================================
# blackmatrix7 Fetching
# =============================================================================

BLACK_FILE_CANDIDATES = ("{name}_Classical.yaml", "{name}.yaml",
                         "{name}_Classical.yml", "{name}.yml")


def load_black_rules(folder_name: str) -> Tuple[List[RuleParts], Optional[str]]:
    encoded_folder = quote_path_part(folder_name)
    for pattern in BLACK_FILE_CANDIDATES:
        filename = pattern.format(name=folder_name)
        text = fetch_optional_text(
            f"{BLACK_RAW_BASE_URL}/{encoded_folder}/"
            f"{quote_path_part(filename)}")
        if text is not None:
            return parse_rule_items(parse_payload_text(text)), filename
    return [], None


# =============================================================================
# Folder Processing
# =============================================================================


def process_folder(folder_name: str) -> Optional[Dict[str, int]]:
    black_rules, black_source = load_black_rules(folder_name)
    meta_rules, meta_stats = load_meta_rules(folder_name)
    if not black_rules and not meta_rules:
        print(f"跳过不存在的规则目录: {folder_name} (两边上游都没有)")
        return None

    merged, meta_added = merge_rule_sets(black_rules, meta_rules)
    dest_folder = DEST_RULE_DIR / folder_name
    dest_folder.mkdir(parents=True, exist_ok=True)

    write_classical_yaml(dest_folder, folder_name, merged, black_source,
                         len(black_rules), meta_stats, len(merged),
                         meta_added)

    domain_entries, ip_entries = split_mrs_rules(merged)
    generated_mrs = compile_rules_to_mrs(dest_folder, folder_name,
                                         domain_entries, ip_entries)
    client_counts = write_client_lists(dest_folder, merged)
    write_readme(dest_folder, folder_name, len(merged),
                 len(domain_entries), len(ip_entries), client_counts,
                 generated_mrs)

    print(f"上游规则转换完成: {folder_name}", flush=True)
    return {
        "black": len(black_rules),
        "meta": meta_stats["geosite"] + meta_stats["geoip"],
        "meta_added": meta_added,
        "merged": len(merged),
        "meta_skipped": meta_stats["skipped"],
    }


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    if not UPSTREAM_INCLUDE_FOLDERS:
        print("名单是空的: 先在 UPSTREAM_INCLUDE_FOLDERS 里写要融合的"
              "规则名, 再运行")
        return
    ensure_mihomo_exists()
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    total_added = 0
    done = 0
    try:
        for folder_name in sorted(UPSTREAM_INCLUDE_FOLDERS):
            result = process_folder(folder_name)
            if result is not None:
                done += 1
                total_added += result["meta_added"]
    finally:
        if TEMP_DIR.exists():
            shutil.rmtree(TEMP_DIR)
    print(f"全部完成: 共处理 {done} 个规则目录, "
          f"MetaCubeX 共补入 {total_added} 条黑矩阵没有的规则")


if __name__ == "__main__":
    main()
