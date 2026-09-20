#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import datetime as _dt
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from io import StringIO
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote

import yaml


# ================= 核心配置 =================

SOURCE_RULE_DIR = Path("source_repo/rule")
SOURCE_CLASH_DIR = SOURCE_RULE_DIR / "Clash"
DEST_RULE_DIR = Path("rule")
TEMP_DIR = Path("temp_compile")

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

UPSTREAM_RAW_RULE_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "blackmatrix7/ios_rule_script/master/rule"
)

MY_RAW_RULE_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "alienwaregf/personal-use/main/rule"
)

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
    "ChinaMax",
    "Claude",
    "Cloudflare",
    "Copilot",
    "Discord",
    "Disney",
    "Docker",
    "Download",
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
    "Mail",
    "Microsoft",
    "Netflix",
    "Nvidia",
    "NTPService",
    "Oracle",
    "OpenAI",
    "PayPal",
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



CLIENT_HEADER_RE = re.compile(
    r"^(#{1,6})\s*"
    r"(?:<img\b[^>]*>\s*)?"
    r"(Clash|Loon|QuantumultX|Shadowrocket|Surge)\s*$",
    re.I,
)


# ================= 客户端 Logo =================

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


# ============================================================
# 目标客户端规则映射
# ============================================================

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


# ================= 通用工具 =================

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


# ================= 文件选择 =================

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


def find_upstream_list_file(
    client: str,
    folder_name: str,
) -> Optional[str]:

    folder = (
        SOURCE_RULE_DIR
        / client
        / folder_name
    )

    preferred = (
        folder
        / f"{folder_name}.list"
    )

    if preferred.is_file():
        return preferred.name

    if not folder.is_dir():
        return None

    candidates = sorted(
        path
        for path in folder.iterdir()
        if (
            path.is_file()
            and path.suffix.lower() == ".list"
        )
    )

    if candidates:
        return candidates[0].name

    return None


# ================= 客户端规则转换 =================

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

    lines: List[str] = []
    mapped_rules: List[str] = []
    counts = Counter()

    for parts in rules:
        target_line = build_client_rule_line(
            parts,
            client,
            folder_name,
        )

        mapped_rules.append(
            target_line
        )

        counts[
            CLIENT_TYPE_MAP[client][
                parts[0].upper()
            ]
        ] += 1

    lines.extend(
        [
            f"# NAME: {folder_name}",
            (
                "# AUTHOR: alienwaregf"
            ),
            (
                "# REPO: "
                "https://github.com/"
                "alienwaregf/personal-use"
            ),
            (
                "# UPDATED: "
                f"{_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            ),
        ]
    )

    for key, count in counts.items():
        lines.append(
            f"# {key}: {count}"
        )

    lines.append(
        f"# TOTAL: {len(mapped_rules)}"
    )

    lines.extend(mapped_rules)

    return (
        "\n".join(lines)
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


# ================= README =================

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
    custom: bool,
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

        if custom:
            classical_url = (
                f"{MY_RAW_RULE_BASE_URL}/"
                f"{folder_url}/"
                f"{quote_path_part(classical_filename)}"
            )

        else:
            classical_url = (
                f"{UPSTREAM_RAW_RULE_BASE_URL}/"
                f"Clash/"
                f"{folder_url}/"
                f"{quote_path_part(classical_filename)}"
            )

        if has_domain_mrs:
            parts.append(
                "domain\n"
                "```text\n"
                f"{MY_RAW_RULE_BASE_URL}/"
                f"{folder_url}/"
                f"{quote_path_part(folder_name + '_Domain.mrs')}\n"
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

    if custom:

        filename = list_filenames.get(
            client,
            f"{client}.list",
        )

        subscription_url = (
            f"{MY_RAW_RULE_BASE_URL}/"
            f"{folder_url}/"
            f"{quote_path_part(filename)}"
        )

    else:

        filename = list_filenames.get(
            client
        )

        if not filename:
            filename = (
                f"{folder_name}.list"
            )

        subscription_url = (
            f"{UPSTREAM_RAW_RULE_BASE_URL}/"
            f"{client}/"
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
    custom: bool,
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
                custom=custom,
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
    # 找到第一个客户端标题
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
    # 如果上游 README 根本没有客户端标题
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
    # 最终重新拼接
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
    custom: bool,
    list_filenames: Optional[
        Dict[str, str]
    ] = None,
    template_path: Optional[Path] = None,
) -> None:



    if (
        template_path
        and template_path.is_file()
    ):

        content = (
            template_path.read_text(
                encoding="utf-8"
            )
        )

    elif readme_path.is_file():

        # 自定义规则没有上游模板，
        # 才使用本地 README。
        content = (
            readme_path.read_text(
                encoding="utf-8"
            )
        )

    else:

        content = (
            f"# 🧸 {folder_name}\n"
        )

    replacement = client_section_text(
        folder_name=folder_name,
        classical_filename=classical_filename,
        has_domain_mrs=has_domain_mrs,
        has_ip_mrs=has_ip_mrs,
        custom=custom,
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


# ================= MRS / 处理单个目录 =================

def compile_rule_set(
    folder_name: str,
    source_yaml: Path,
    destination_folder: Path,
) -> Tuple[
    bool,
    bool,
    List[List[str]],
]:

    rules = parse_rules(
        source_yaml
    )

    if not rules:
        raise RuntimeError(
            "未解析出任何有效 Clash 规则: "
            f"{source_yaml}"
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
                / f"{folder_name}_Domain.mrs"
            ),
            "domain",
        )

    elif (
        destination_folder
        / f"{folder_name}_Domain.mrs"
    ).exists():

        (
            destination_folder
            / f"{folder_name}_Domain.mrs"
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
        rules,
    )


def process_upstream_folder(
    folder_name: str,
) -> None:

    source_folder = (
        SOURCE_CLASH_DIR
        / folder_name
    )

    if not source_folder.is_dir():

        print(
            f"跳过上游目录："
            f"{source_folder}"
        )

        return

    source_yaml = select_best_yaml(
        source_folder,
        folder_name,
    )

    if not source_yaml:

        print(
            "跳过上游目录，没有 YAML："
            f"{folder_name}"
        )

        return

    dest = (
        DEST_RULE_DIR
        / folder_name
    )

    dest.mkdir(
        parents=True,
        exist_ok=True,
    )

    has_domain, has_ip, _rules = (
        compile_rule_set(
            folder_name,
            source_yaml,
            dest,
        )
    )

    # =========================================================
    # Clash Classical
    # =========================================================

    classical_filename = (
        f"{folder_name}_Classical.yaml"
    )

    if not (
        source_folder
        / classical_filename
    ).is_file():

        classical_filename = (
            source_yaml.name
        )

    # =========================================================
    # 获取上游客户端规则文件
    # =========================================================

    list_filenames: Dict[str, str] = {}

    for client in NON_CLASH_CLIENTS:

        filename = (
            find_upstream_list_file(
                client,
                folder_name,
            )
        )

        if filename:

            list_filenames[client] = (
                filename
            )

        else:

            raise RuntimeError(
                "上游缺少 "
                f"{client} 规则文件: "
                f"{folder_name}"
            )

    # =========================================================
    # 使用 Blackmatrix7 README 作为模板
    # =========================================================

    template = (
        source_folder
        / "README.md"
    )

    update_readme(
        DEST_RULE_DIR
        / folder_name
        / "README.md",

        folder_name,

        classical_filename,

        has_domain,

        has_ip,

        custom=False,

        list_filenames=list_filenames,

        template_path=template,
    )


# ================= 自定义规则 =================

def is_custom_rule_folder(
    folder: Path,
) -> bool:

    if not folder.is_dir():
        return False

    if (
        folder.name
        in UPSTREAM_INCLUDE_FOLDERS
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


def process_custom_folder(
    folder: Path,
) -> None:

    folder_name = folder.name

    source_yaml = (
        select_best_yaml(
            folder,
            folder_name,
        )
    )

    if not source_yaml:
        return

    has_domain, has_ip, rules = (
        compile_rule_set(
            folder_name,
            source_yaml,
            folder,
        )
    )

    # =========================================================
    # 四个非 Clash 客户端
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
        source_yaml.name,
        has_domain,
        has_ip,
        custom=True,
        list_filenames=list_filenames,
    )

    print(
        "自定义规则完成: "
        f"{folder_name}"
    )


# ================= 主流程 =================

def ensure_mihomo_available() -> None:

    if not shutil.which("mihomo"):
        raise RuntimeError(
            "找不到 mihomo 命令"
        )


def main() -> None:

    print(
        "开始执行规则转换..."
    )

    print(
        "上游规则：生成 MRS + README；"
        "README 以 Blackmatrix7 最新版本为母版，"
        "自动生成 Clash / Loon / QuantumultX / "
        "Shadowrocket / Surge 五个客户端模块，"
        "并保留上游其他 README 内容。"
    )

    print(
        "自定义规则：从本地 Clash YAML "
        "生成 Loon / QuantumultX / "
        "Shadowrocket / Surge 规则文件。"
    )

    print(
        "清理策略：不删除任何用户目录。"
    )

    ensure_mihomo_available()

    if not SOURCE_CLASH_DIR.is_dir():
        raise RuntimeError(
            "找不到上游 Clash 目录: "
            f"{SOURCE_CLASH_DIR}"
        )

    # =========================================================
    # 临时目录
    # =========================================================

    if TEMP_DIR.exists():
        shutil.rmtree(
            TEMP_DIR
        )

    TEMP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    DEST_RULE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # =========================================================
    # 处理 Blackmatrix7 上游规则
    # =========================================================

    for folder_name in sorted(
        UPSTREAM_INCLUDE_FOLDERS
    ):

        process_upstream_folder(
            folder_name
        )

    # =========================================================
    # 处理 rule/ 下用户自己的自定义规则
    # =========================================================

    for folder in sorted(
        DEST_RULE_DIR.iterdir(),
        key=lambda p: p.name.lower(),
    ):

        if is_custom_rule_folder(
            folder
        ):

            process_custom_folder(
                folder
            )

    print(
        "\n规则转换完成。"
    )


if __name__ == "__main__":

    try:
        main()

    finally:

        if TEMP_DIR.exists():
            shutil.rmtree(
                TEMP_DIR,
                ignore_errors=True,
            )
