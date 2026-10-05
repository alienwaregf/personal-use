#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import email.utils
import urllib.request
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from io import StringIO
from typing import Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote

import yaml

DEST_RULE_DIR = Path("rule")
TEMP_DIR = Path("temp_compile")

CUSTOM_CACHE_PATH = DEST_RULE_DIR / ".compile_cache_custom.json"

CLIENTS = (
    "Clash",
    "Loon",
    "QuantumultX",
    "Shadowrocket",
    "Surge",
)

NON_CLASH_CLIENTS = tuple(
    client for client in CLIENTS
    if client != "Clash"
)

RESERVED_DIRS = set(CLIENTS) | {".git"}

MY_RAW_RULE_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "alienwaregf/personal-use/main/rule"
)

SCRIPT_OWNED_FOLDERS = {
    "AD",
    "Adult",
}

CLIENT_HEADER_RE = re.compile(
    r"^(#{1,6})\s*"
    r"(?:<img\b[^>]*>\s*)?"
    r"(Clash|Loon|QuantumultX|Shadowrocket|Surge)\s*$",
    re.I,
)

UPSTREAM_FOLDERS = {
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

CLIENT_TYPE_MAP: Dict[str, Dict[str, str]] = {
    "Loon": {
        "DOMAIN": "DOMAIN",
        "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
        "USER-AGENT": "USER-AGENT",
        "URL-REGEX": "URL-REGEX",
        "IP-CIDR": "IP-CIDR",
        "IP-CIDR6": "IP-CIDR6",
    },

    "QuantumultX": {
        "DOMAIN": "HOST",
        "DOMAIN-SUFFIX": "HOST-SUFFIX",
        "DOMAIN-KEYWORD": "HOST-KEYWORD",
        "DOMAIN-WILDCARD": "HOST-WILDCARD",
        "USER-AGENT": "USER-AGENT",
        "URL-REGEX": "URL-REGEX",
        "IP-CIDR": "IP-CIDR",
        "IP-CIDR6": "IP6-CIDR",
    },

    "Shadowrocket": {
        "DOMAIN": "DOMAIN",
        "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
        "USER-AGENT": "USER-AGENT",
        "URL-REGEX": "URL-REGEX",
        "IP-CIDR": "IP-CIDR",
        "IP-CIDR6": "IP-CIDR",
    },

    "Surge": {
        "DOMAIN": "DOMAIN",
        "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
        "USER-AGENT": "USER-AGENT",
        "URL-REGEX": "URL-REGEX",
        "IP-CIDR": "IP-CIDR",
        "IP-CIDR6": "IP-CIDR6",
        "PROCESS-NAME": "PROCESS-NAME",
    },
}

def quote_path_part(value: str) -> str:
    return quote(str(value), safe="")

def strip_yaml_quote(value: object) -> str:
    value = str(value).strip()

    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in ("'", '"')
    ):
        return value[1:-1].strip()

    return value

def parse_payload_rule_line(
    line: object,
) -> Optional[List[str]]:
    if line is None:
        return None

    raw = str(line).strip()

    if not raw:
        return None

    if raw.startswith("-"):
        raw = raw[1:].strip()

    if " #" in raw:
        raw = raw.split(" #", 1)[0].rstrip()

    raw = strip_yaml_quote(raw)

    if not raw or raw.startswith("#"):
        return None

    try:
        row = next(
            csv.reader(
                [raw],
                skipinitialspace=True,
            )
        )
    except csv.Error as exc:
        raise ValueError(
            f"无法解析 Clash 规则: {raw}"
        ) from exc

    return [
        strip_yaml_quote(part.strip())
        for part in row
        if part.strip()
    ]

def load_yaml_payload(
    filepath: Path,
) -> List[str]:
    try:
        data = yaml.safe_load(
            filepath.read_text(
                encoding="utf-8"
            )
        )

        if (
            isinstance(data, dict)
            and isinstance(data.get("payload"), list)
        ):
            return [
                str(item).strip()
                for item in data["payload"]
                if (
                    item is not None
                    and str(item).strip()
                )
            ]

        if isinstance(data, list):
            return [
                str(item).strip()
                for item in data
                if (
                    item is not None
                    and str(item).strip()
                )
            ]

    except Exception as exc:
        print(
            f"PyYAML 读取失败，改用按行解析: "
            f"{filepath}"
        )
        print(f"原因: {exc}")

    payload: List[str] = []
    payload_started = False

    for line in filepath.read_text(
        encoding="utf-8"
    ).splitlines():

        stripped = line.strip()

        if stripped == "payload:":
            payload_started = True
            continue

        if (
            not payload_started
            or not stripped.startswith("-")
        ):
            continue

        parsed = parse_payload_rule_line(
            stripped
        )

        if parsed:
            payload.append(
                ",".join(parsed)
            )

    return payload

def parse_rules(
    filepath: Path,
) -> List[List[str]]:
    rules: List[List[str]] = []
    seen: Set[Tuple[str, ...]] = set()

    for raw in load_yaml_payload(filepath):
        parts = parse_payload_rule_line(raw)

        if not parts:
            continue

        key = tuple(parts)

        if key in seen:
            continue

        seen.add(key)
        rules.append(parts)

    return rules

DOMAIN_COMPRESSION_THRESHOLD = 2

def fetch_text(
    url: str,
    user_agent: str,
    timeout: int = 60,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> Tuple[str, Optional[datetime]]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": user_agent},
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as resp:
            status = resp.status
            raw = resp.read()
            headers = resp.headers
    except Exception as exc:
        raise RuntimeError(
            f"拉取上游规则失败: {url}"
        ) from exc

    if status != 200:
        raise RuntimeError(
            f"上游返回 HTTP {status}: {url}"
        )

    last_modified: Optional[datetime] = None

    header_value = headers.get("Last-Modified")

    if header_value:
        try:
            parsed = email.utils.parsedate_to_datetime(
                header_value
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            last_modified = parsed.astimezone(
                timezone.utc
            )
        except (TypeError, ValueError):
            last_modified = None

    return (
        raw.decode(encoding, errors=errors),
        last_modified,
    )


SOURCE_DOMAIN_RE = re.compile(
    r"^(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def parse_abp_line(
    line: str,
) -> Tuple[Optional[Tuple[str, str]], str]:
    text = line.strip()

    if (
        not text
        or text.startswith("!")
        or text.startswith("[")
    ):
        return None, "comment"

    if (
        "##" in text
        or "#@#" in text
        or "#?#" in text
        or "#$#" in text
    ):
        return None, "cosmetic"

    is_exception = text.startswith("@@")

    if is_exception:
        text = text[2:]

    if not text.startswith("||"):
        return None, "non-domain-rule"

    body = text[2:]
    pattern, _, options = body.partition("$")

    if "domain=" in options:
        return None, "site-scoped"

    if options:
        return None, "has-options"

    if not pattern.endswith("^"):
        return None, "not-caret-terminated"

    domain = pattern[:-1].lower().rstrip(".")

    if SOURCE_DOMAIN_RE.match(domain):

        if is_exception:
            return None, "exception"

        return ("DOMAIN-SUFFIX", domain), "ok"

    try:
        ip = ipaddress.ip_address(
            domain
        )
    except ValueError:
        return None, "bad-domain"

    if is_exception:
        return None, "exception"

    mask = 32 if ip.version == 4 else 128

    return ("IP-CIDR", f"{domain}/{mask}"), "ok"


def parse_hosts_line(
    line: str,
) -> Tuple[Optional[Tuple[str, str]], str]:
    text = line.strip()

    if not text or text.startswith("#"):
        return None, "comment"

    parts = text.split()

    if len(parts) < 2 or parts[0] != "0.0.0.0":
        return None, "non-hosts-line"

    domain = parts[1].lower().rstrip(".")

    if not SOURCE_DOMAIN_RE.match(domain):
        return None, "bad-domain"

    return ("DOMAIN", domain), "ok"


def parse_domains_line(
    line: str,
) -> Tuple[Optional[Tuple[str, str]], str]:
    text = line.strip()

    if (
        not text
        or text.startswith("#")
        or text.startswith("!")
    ):
        return None, "comment"

    domain = text.lower().rstrip(".")

    if not SOURCE_DOMAIN_RE.match(domain):
        return None, "bad-domain"

    return ("DOMAIN-SUFFIX", domain), "ok"


SOURCE_PARSERS = {
    "abp": parse_abp_line,
    "hosts": parse_hosts_line,
    "domains": parse_domains_line,
}


def gather_source_rules(
    sources: Dict[str, Tuple[str, str]],
    user_agent: str,
    timeout: int = 60,
) -> Tuple[
    List[Tuple[str, str]],
    Dict[str, Dict[str, int]],
    Dict[str, Optional[datetime]],
]:
    merged: Set[Tuple[str, str]] = set()
    stats: Dict[str, Dict[str, int]] = {}
    updated_times: Dict[str, Optional[datetime]] = {}

    for name, (url, kind) in sources.items():
        print(f"拉取 {name}: {url}")

        text, last_modified = fetch_text(
            url,
            user_agent,
            timeout=timeout,
            errors="replace",
        )

        parser = SOURCE_PARSERS[kind]

        hosts_domains: Set[str] = set()

        source_stats: Dict[str, int] = {
            "lines": 0,
            "ok": 0,
        }

        for raw_line in text.splitlines():
            source_stats["lines"] += 1

            rule, reason = parser(
                raw_line
            )

            if rule:
                source_stats["ok"] += 1

                if kind == "hosts":
                    hosts_domains.add(rule[1])
                else:
                    merged.add(rule)
            else:
                source_stats[reason] = (
                    source_stats.get(reason, 0) + 1
                )

        if source_stats["ok"] == 0:
            raise RuntimeError(
                f"{name} 未提取到任何规则，"
                f"上游可能已变更格式: {url}"
            )

        if kind == "hosts":
            marked = compress_domains(
                hosts_domains
            )

            merged.update(
                domains_to_rules(marked)
            )

        stats[name] = source_stats
        updated_times[name] = last_modified

        skip_detail = ", ".join(
            f"{key}={source_stats[key]}"
            for key in sorted(source_stats)
            if (
                key not in ("lines", "ok")
                and source_stats[key]
            )
        )

        print(
            f"  {name}: {source_stats['lines']} 行 -> "
            f"{source_stats['ok']} 条规则 "
            f"({skip_detail})"
        )

    return sorted(merged), stats, updated_times


def parent_suffixes(host: str) -> List[str]:
    labels = host.split(".")

    if len(labels) < 3:
        return []

    return [
        ".".join(labels[i:])
        for i in range(0, len(labels) - 2)
    ]

def compress_domains(domains: Set[str]) -> Set[str]:
    suffix_members: Dict[str, Set[str]] = defaultdict(set)

    for domain in domains:
        for suffix in parent_suffixes(domain):
            suffix_members[suffix].add(domain)

    candidates = [
        (suffix, members)
        for suffix, members in suffix_members.items()
        if len(members) >= DOMAIN_COMPRESSION_THRESHOLD
    ]

    candidates.sort(
        key=lambda item: len(item[0].split(".")),
        reverse=True,
    )

    remaining = set(domains)
    output: Set[str] = set()
    compressed = 0

    for suffix, _ in candidates:
        members = {
            domain
            for domain in remaining
            if domain == suffix or domain.endswith("." + suffix)
        }

        if len(members) < DOMAIN_COMPRESSION_THRESHOLD:
            continue

        output.add(f"+.{suffix}")
        remaining.difference_update(members)
        compressed += 1

    output.update(remaining)

    print(
        f"域名压缩: {len(domains):,} → {len(output):,} "
        f"（合并 {compressed:,} 个父域）"
    )

    return output

def domains_to_rules(
    domains: Set[str],
) -> List[Tuple[str, str]]:
    rules: List[Tuple[str, str]] = []

    for domain in sorted(domains):
        if domain.startswith("+."):
            rules.append(
                (
                    "DOMAIN-SUFFIX",
                    domain[2:].lstrip("."),
                )
            )
        else:
            rules.append(
                ("DOMAIN", domain)
            )

    return rules

def split_mrs_rules(
    rules: Sequence[Sequence[str]],
) -> Tuple[List[str], List[str]]:

    domain_rules: List[str] = []
    ip_rules: List[str] = []

    domain_seen: Set[str] = set()
    ip_seen: Set[str] = set()

    for parts in rules:
        if len(parts) < 2:
            continue

        rule_type = parts[0].upper()
        value = strip_yaml_quote(parts[1])

        if not value:
            continue

        if rule_type == "DOMAIN":
            result = value

        elif rule_type == "DOMAIN-SUFFIX":
            result = (
                f"+."
                f"{value.removeprefix('+.').lstrip('.')}"
            )

        elif rule_type in {
            "DOMAIN-KEYWORD",
            "DOMAIN-WILDCARD",
        }:
            continue

        else:
            result = None

        if (
            result is not None
            and result not in domain_seen
        ):
            domain_seen.add(result)
            domain_rules.append(result)
            continue

        if rule_type in {
            "IP-CIDR",
            "IP-CIDR6",
        }:
            try:
                ipaddress.ip_network(
                    value,
                    strict=False,
                )
            except ValueError:
                raise ValueError(
                    f"非法 CIDR: {','.join(parts)}"
                )

            if value not in ip_seen:
                ip_seen.add(value)
                ip_rules.append(value)

    return domain_rules, ip_rules

def write_mrs_source_yaml(
    path: Path,
    rules: Sequence[str],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as fh:

        fh.write("payload:\n")

        for rule in rules:
            dumped = yaml.safe_dump(
                rule,
                allow_unicode=True,
                default_flow_style=True,
            ).strip()

            fh.write(
                "  - "
                + dumped
                + "\n"
            )

def compile_to_mrs(
    temp_yaml_path: Path,
    output_path: Path,
    behavior: str,
) -> None:

    mihomo = shutil.which("mihomo")

    if not mihomo:
        raise RuntimeError(
            "找不到 mihomo 命令"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    command = [
        mihomo,
        "convert-ruleset",
        behavior,
        "yaml",
        str(temp_yaml_path),
        str(output_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        details = "\n".join(
            x.strip()
            for x in (
                result.stdout,
                result.stderr,
            )
            if x and x.strip()
        )

        raise RuntimeError(
            f"Mihomo 转换失败: "
            f"{' '.join(command)}\n"
            f"{details}"
        )

    if (
        not output_path.exists()
        or output_path.stat().st_size == 0
    ):
        raise RuntimeError(
            f"Mihomo 未生成有效 MRS: "
            f"{output_path}"
        )

def compile_parsed_rules(
    folder_name: str,
    rules: Sequence[Sequence[str]],
    destination_folder: Path,
) -> Tuple[bool, bool]:

    if not rules:
        raise RuntimeError(
            "未解析出任何有效 Clash 规则: "
            f"{folder_name}"
        )

    domain_rules, ip_rules = (
        split_mrs_rules(rules)
    )

    destination_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    has_domain = bool(
        domain_rules
    )

    has_ip = bool(
        ip_rules
    )

    # =========================================================
    # Domain MRS
    # =========================================================

    if has_domain:

        temp = (
            TEMP_DIR
            / f"{folder_name}_domain.yaml"
        )

        write_mrs_source_yaml(
            temp,
            domain_rules,
        )

        compile_to_mrs(
            temp,
            (
                destination_folder
                / f"{folder_name}.mrs"
            ),
            "domain",
        )

    elif (
        destination_folder
        / f"{folder_name}.mrs"
    ).exists():

        (
            destination_folder
            / f"{folder_name}.mrs"
        ).unlink()

    # =========================================================
    # IP MRS
    # =========================================================

    if has_ip:

        temp = (
            TEMP_DIR
            / f"{folder_name}_ip.yaml"
        )

        write_mrs_source_yaml(
            temp,
            ip_rules,
        )

        compile_to_mrs(
            temp,
            (
                destination_folder
                / f"{folder_name}_IP.mrs"
            ),
            "ipcidr",
        )

    elif (
        destination_folder
        / f"{folder_name}_IP.mrs"
    ).exists():

        (
            destination_folder
            / f"{folder_name}_IP.mrs"
        ).unlink()

    return (
        has_domain,
        has_ip,
    )

def select_best_yaml(
    folder_path: Path,
    folder_name: str,
) -> Optional[Path]:

    candidates = [
        folder_path
        / f"{folder_name}_Classical.yaml",

        folder_path
        / f"{folder_name}.yaml",
    ]

    for path in candidates:
        if path.is_file():
            return path

    yaml_files = sorted(
        path
        for path in folder_path.iterdir()
        if (
            path.is_file()
            and path.suffix.lower()
            in {".yaml", ".yml"}
        )
    )

    return (
        yaml_files[0]
        if yaml_files
        else None
    )

def _extra_options(
    parts: Sequence[str],
) -> List[str]:

    return [
        str(x).strip()
        for x in parts[2:]
        if str(x).strip()
    ]

def build_client_rule_line(
    parts: Sequence[str],
    client: str,
    policy_name: str,
) -> str:

    if not parts:
        raise ValueError("空规则")

    source_type = parts[0].upper()
    mapping = CLIENT_TYPE_MAP[client]

    if source_type not in mapping:
        raise ValueError(
            f"{client} 无法无损表示 Clash "
            f"规则类型: {source_type}"
        )

    if len(parts) < 2:
        raise ValueError(
            f"规则缺少值: {','.join(parts)}"
        )

    value = strip_yaml_quote(
        parts[1]
    )

    if not value:
        raise ValueError(
            f"规则值为空: {','.join(parts)}"
        )

    target_type = mapping[source_type]
    extras = _extra_options(parts)

    unsupported_extras = [
        x
        for x in extras
        if x != "no-resolve"
    ]

    if unsupported_extras:
        raise ValueError(
            f"{client} 无法确认附加参数的"
            f"等价语义: {','.join(parts)}"
        )

    fields = [
        target_type,
        value,
    ]

    if client == "QuantumultX":
        fields.append(policy_name)

    if "no-resolve" in extras:
        fields.append("no-resolve")

    buffer = StringIO()

    writer = csv.writer(
        buffer,
        lineterminator="",
        quoting=csv.QUOTE_MINIMAL,
    )

    writer.writerow(fields)

    return buffer.getvalue()

def build_client_list(
    folder_name: str,
    rules: Sequence[Sequence[str]],
    client: str,
) -> str:

    mapped_rules: List[str] = []

    for parts in rules:
        if not parts:
            continue

        source_type = parts[0].upper()

        if source_type not in CLIENT_TYPE_MAP[client]:
            print(
                f"跳过 {client} 不支持的规则类型: "
                f"{source_type}"
            )
            continue

        target_line = build_client_rule_line(
            parts,
            client,
            folder_name,
        )

        mapped_rules.append(
            target_line
        )

    return (
        "\n".join(mapped_rules)
        + "\n"
    )

def write_client_lists(
    folder: Path,
    folder_name: str,
    rules: Sequence[Sequence[str]],
) -> None:

    for client in NON_CLASH_CLIENTS:
        output = (
            folder
            / f"{client}.list"
        )

        output.write_text(
            build_client_list(
                folder_name,
                rules,
                client,
            ),
            encoding="utf-8",
            newline="\n",
        )

def client_heading(
    client: str,
) -> str:

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
    list_filenames: Dict[str, str],
) -> str:

    folder_url = quote_path_part(
        folder_name
    )

    parts: List[str] = []

    parts.append(
        client_heading(client)
    )

    # =========================================================
    # Clash
    # =========================================================

    if client == "Clash":

        classical_url = (
            f"{MY_RAW_RULE_BASE_URL}/"
            f"{folder_url}/"
            f"{quote_path_part(classical_filename)}"
        )

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
            f"{classical_url}\n"
            "```\n\n"
        )

        return "".join(parts)

    # =========================================================
    # Loon / QuantumultX / Shadowrocket / Surge
    # =========================================================

    filename = list_filenames.get(
        client,
        f"{client}.list",
    )

    subscription_url = (
        f"{MY_RAW_RULE_BASE_URL}/"
        f"{folder_url}/"
        f"{quote_path_part(filename)}"
    )

    parts.append(
        "```text\n"
        f"{subscription_url}\n"
        "```\n\n"
    )

    return "".join(parts)

def client_section_text(
    folder_name: str,
    classical_filename: str,
    has_domain_mrs: bool,
    has_ip_mrs: bool,
    list_filenames: Optional[
        Dict[str, str]
    ] = None,
) -> str:

    list_filenames = (
        list_filenames or {}
    )

    sections: List[str] = []

    for client in CLIENTS:
        sections.append(
            build_client_section(
                client=client,
                folder_name=folder_name,
                classical_filename=classical_filename,
                has_domain_mrs=has_domain_mrs,
                has_ip_mrs=has_ip_mrs,
                list_filenames=list_filenames,
            ).rstrip()
        )

    return (
        "\n\n".join(sections)
    )

def replace_client_sections(
    content: str,
    replacement: str,
) -> str:

    lines = content.splitlines(
        keepends=True
    )

    # =========================================================
    # =========================================================

    first_client_index: Optional[int] = None

    for idx, line in enumerate(lines):

        match = CLIENT_HEADER_RE.match(
            line.strip()
        )

        if match:
            first_client_index = idx
            break

    preserve_patterns = (
        re.compile(
            r"^##\s+子规则/排除规则\s*$"
        ),
        re.compile(
            r"^##\s+数据来源\s*$"
        ),
        re.compile(
            r"^##\s+最后\s*$"
        ),
    )

    preserve_index: Optional[int] = None

    search_start = (
        first_client_index
        if first_client_index is not None
        else 0
    )

    for idx in range(
        search_start,
        len(lines),
    ):

        stripped = lines[idx].strip()

        if any(
            pattern.match(stripped)
            for pattern in preserve_patterns
        ):
            preserve_index = idx
            break

    # =========================================================
    # =========================================================

    if first_client_index is None:

        if preserve_index is not None:

            prefix = "".join(
                lines[:preserve_index]
            ).rstrip()

            suffix = "".join(
                lines[preserve_index:]
            ).lstrip()

            result_parts: List[str] = []

            if prefix:
                result_parts.append(
                    prefix
                )

            result_parts.append(
                replacement.rstrip()
            )

            if suffix:
                result_parts.append(
                    suffix.rstrip()
                )

            return (
                "\n\n".join(
                    result_parts
                )
                + "\n"
            )

        base = content.rstrip()

        if base:
            return (
                base
                + "\n\n"
                + replacement.rstrip()
                + "\n"
            )

        return (
            replacement.rstrip()
            + "\n"
        )

    prefix = "".join(
        lines[:first_client_index]
    ).rstrip()

    suffix = ""

    if preserve_index is not None:

        suffix = "".join(
            lines[preserve_index:]
        ).lstrip()

    # =========================================================
    # =========================================================

    result_parts: List[str] = []

    if prefix:
        result_parts.append(
            prefix
        )

    result_parts.append(
        replacement.rstrip()
    )

    if suffix:
        result_parts.append(
            suffix.rstrip()
        )

    return (
        "\n\n".join(
            result_parts
        )
        + "\n"
    )

def update_readme(
    readme_path: Path,
    folder_name: str,
    classical_filename: str,
    has_domain_mrs: bool,
    has_ip_mrs: bool,
    list_filenames: Optional[
        Dict[str, str]
    ] = None,
) -> None:

    content = ""

    replacement = client_section_text(
        folder_name=folder_name,
        classical_filename=classical_filename,
        has_domain_mrs=has_domain_mrs,
        has_ip_mrs=has_ip_mrs,
        list_filenames=list_filenames,
    )

    result = replace_client_sections(
        content,
        replacement,
    )

    readme_path.write_text(
        result,
        encoding="utf-8",
        newline="\n",
    )

def _normalized_file_hash(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    for raw_line in path.read_bytes().splitlines():
        line = raw_line.strip()

        if not line or line.startswith(b"#"):
            continue

        digest.update(line)
        digest.update(b"\n")

    return digest.hexdigest()

def _file_sha256(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()

def get_mihomo_version() -> str:
    mihomo = shutil.which("mihomo")

    if not mihomo:
        raise RuntimeError(
            "找不到 mihomo 命令"
        )

    result = subprocess.run(
        [mihomo, "-v"],
        capture_output=True,
        text=True,
        check=False,
    )

    output = (
        result.stdout
        + result.stderr
    ).strip().splitlines()

    if not output:
        raise RuntimeError(
            "无法获取 mihomo 版本"
        )

    return output[0].strip()

class CompileCache:

    def __init__(
        self,
        path: Path,
        converter_hash: str,
        mihomo_version: str,
    ) -> None:
        self.path = path
        self.converter_hash = converter_hash
        self.mihomo_version = mihomo_version
        self.data: Dict[str, str] = {}

        try:
            raw = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(raw, dict):
                folders = raw.get("folders")

                if isinstance(folders, dict):
                    self.data = {
                        str(name): str(key)
                        for name, key in folders.items()
                    }
        except Exception:
            self.data = {}

    def key_for(
        self,
        source_paths: Sequence[Path],
        raw_paths: Sequence[Path] = (),
    ) -> str:
        digest = hashlib.sha256()

        for path in source_paths:
            try:
                digest.update(
                    _normalized_file_hash(
                        path
                    ).encode()
                )
            except Exception:
                digest.update(b"\x00unreadable\x00")
                digest.update(
                    str(path).encode()
                )

        for path in raw_paths:
            try:
                digest.update(
                    _file_sha256(
                        path
                    ).encode()
                )
            except Exception:
                digest.update(b"\x00unreadable\x00")
                digest.update(
                    str(path).encode()
                )

        digest.update(
            self.converter_hash.encode()
        )
        digest.update(
            self.mihomo_version.encode()
        )

        return digest.hexdigest()

    def is_unchanged(
        self,
        folder_name: str,
        key: str,
    ) -> bool:
        return (
            self.data.get(folder_name)
            == key
        )

    def mark_done(
        self,
        folder_name: str,
        key: str,
    ) -> None:
        self.data[folder_name] = key

    def prune(
        self,
        keep: Set[str],
    ) -> None:
        for name in list(self.data):
            if name not in keep:
                del self.data[name]

    def save(self) -> None:
        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "version": 1,
                "converter_sha256": (
                    self.converter_hash
                ),
                "mihomo_version": (
                    self.mihomo_version
                ),
                "folders": self.data,
            }

            self.path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
        except Exception as exc:
            print(
                f"警告：编译缓存写入失败"
                f"（下次将全量重做）：{exc}"
            )

def make_cache() -> Optional[CompileCache]:
    try:
        return CompileCache(
            CUSTOM_CACHE_PATH,
            _file_sha256(
                Path(__file__)
            ),
            get_mihomo_version(),
        )
    except Exception as exc:
        print(
            f"警告：编译缓存初始化失败"
            f"（本次全量重编）：{exc}"
        )

        return None

def save_cache(
    cache: Optional[CompileCache],
) -> None:
    if cache is not None:
        cache.save()

def prepare_temp_dir() -> None:
    if TEMP_DIR.exists():
        shutil.rmtree(
            TEMP_DIR
        )

    TEMP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

def cleanup_temp_dir() -> None:
    if TEMP_DIR.exists():
        shutil.rmtree(
            TEMP_DIR,
            ignore_errors=True,
        )

def ensure_mihomo_available() -> None:

    if not shutil.which("mihomo"):
        raise RuntimeError(
            "找不到 mihomo 命令"
        )

def is_custom_rule_folder(
    folder: Path,
) -> bool:

    if not folder.is_dir():
        return False

    if (
        folder.name
        in UPSTREAM_FOLDERS
        or folder.name
        in SCRIPT_OWNED_FOLDERS
        or folder.name
        in RESERVED_DIRS
    ):
        return False

    if folder.name.startswith("."):
        return False

    return (
        select_best_yaml(
            folder,
            folder.name,
        )
        is not None
    )

def emit_folder_outputs(
    folder: Path,
    classical_filename: str,
    rules: Sequence[Sequence[str]],
    cache: Optional[CompileCache],
    cache_key: Optional[str],
) -> None:
    folder_name = folder.name

    has_domain, has_ip = (
        compile_parsed_rules(
            folder_name,
            rules,
            folder,
        )
    )

    # =========================================================
    # =========================================================

    write_client_lists(
        folder,
        folder_name,
        rules,
    )

    list_filenames = {
        client: f"{client}.list"
        for client in NON_CLASH_CLIENTS
    }

    update_readme(
        folder / "README.md",
        folder_name,
        classical_filename,
        has_domain,
        has_ip,
        list_filenames=list_filenames,
    )

    if (
        cache is not None
        and cache_key is not None
    ):
        cache.mark_done(
            folder_name,
            cache_key,
        )

def write_classical_yaml(
    path: Path,
    header_lines: List[str],
    rules: List[Tuple[str, str]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = list(header_lines)
    lines.append("payload:")

    lines.extend(
        f"  - {kind},{value}"
        for kind, value in rules
    )

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def emit_folder(
    folder_dir: Path,
    yaml_path: Path,
    rules: List[Tuple[str, str]],
) -> None:
    ensure_mihomo_available()
    prepare_temp_dir()

    cache = make_cache()

    cache_key = (
        cache.key_for([yaml_path])
        if cache is not None
        else None
    )

    try:
        convert_prepared_folder(
            folder_dir,
            yaml_path.name,
            rules,
            cache,
            cache_key,
        )
    finally:
        cleanup_temp_dir()

    save_cache(cache)


def convert_prepared_folder(
    folder: Path,
    classical_filename: str,
    rules: Sequence[Sequence[str]],
    cache: Optional[CompileCache],
    cache_key: Optional[str],
) -> str:
    folder_name = folder.name

    if (
        cache is not None
        and cache_key is not None
        and cache.is_unchanged(
            folder_name,
            cache_key,
        )
    ):
        print(
            f"跳过未变化的目录："
            f"{folder_name}"
        )

        return folder_name

    emit_folder_outputs(
        folder,
        classical_filename,
        rules,
        cache,
        cache_key,
    )

    print(
        "规则转换完成: "
        f"{folder_name}"
    )

    return folder_name

def convert_custom_folder(
    folder: Path,
    cache: Optional[CompileCache],
) -> Optional[str]:

    folder_name = folder.name

    source_yaml = (
        select_best_yaml(
            folder,
            folder_name,
        )
    )

    if not source_yaml:
        return None

    # =========================================================
    # =========================================================

    cache_key: Optional[str] = None

    if cache is not None:
        cache_key = cache.key_for(
            [source_yaml]
        )

        if cache.is_unchanged(
            folder_name,
            cache_key,
        ):
            print(
                f"跳过未变化的自定义目录："
                f"{folder_name}"
            )

            return folder_name

    rules = parse_rules(
        source_yaml
    )

    emit_folder_outputs(
        folder,
        source_yaml.name,
        rules,
        cache,
        cache_key,
    )

    print(
        "自定义规则完成: "
        f"{folder_name}"
    )

    return folder_name

