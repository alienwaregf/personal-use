#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import rule_converter

SOURCES: Dict[str, Tuple[str, str]] = {
    "easylist": (
        "https://easylist-downloads.adblockplus.org/"
        "easylist.txt",
        "abp",
    ),
    "easyprivacy": (
        "https://easylist-downloads.adblockplus.org/"
        "easyprivacy.txt",
        "abp",
    ),
    "easylistchina": (
        "https://easylist-downloads.adblockplus.org/"
        "easylistchina.txt",
        "abp",
    ),
    "hagezi-ultimate": (
        "https://raw.githubusercontent.com/"
        "hagezi/dns-blocklists/main/adblock/ultimate.txt",
        "abp",
    ),
    "stevenblack": (
        "https://raw.githubusercontent.com/"
        "StevenBlack/hosts/master/hosts",
        "hosts",
    ),
    "anti-ad": (
        "https://raw.githubusercontent.com/"
        "privacy-protection-tools/anti-AD/master/"
        "anti-ad-domains.txt",
        "domains",
    ),
}

OUTPUT_DIR = Path("rule") / "AD"
OUTPUT_FILE = OUTPUT_DIR / "AD.yaml"

USER_AGENT = "personal-use-ad-sync/1.0"


def build_yaml_header(
    rules: List[Tuple[str, str]],
    stats: Dict[str, Dict[str, int]],
    updated_times: Dict[str, Optional[datetime]],
) -> List[str]:
    exact_count = sum(
        1 for kind, _ in rules if kind == "DOMAIN"
    )

    suffix_count = sum(
        1 for kind, _ in rules if kind == "DOMAIN-SUFFIX"
    )

    ip_count = sum(
        1 for kind, _ in rules if kind == "IP-CIDR"
    )

    lines = [
        "# AD 聚合广告域名规则",
        "# 由 Scripts/AD_rule.py 自动生成，请勿手动修改",
        "# 数据来源：",
    ]

    for name, (url, _kind) in SOURCES.items():
        source_stats = stats[name]
        source_updated = updated_times[name]

        if source_updated is not None:
            updated_text = source_updated.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            updated_text = "未知"

        lines.append(f"#   - {name}: {url}")
        lines.append(
            f"#     原始 {source_stats['lines']} 行，"
            f"提取 {source_stats['ok']} 条规则；"
            f"最后更新时间（UTC）：{updated_text}"
        )

    lines.append(
        f"# 合并去重后：域名 {exact_count + suffix_count} 个，"
        f"IP 规则 {ip_count} 条"
    )

    return lines


def main() -> None:
    print("开始拉取聚合广告域名规则...")

    rules, stats, updated_times = (
        rule_converter.gather_source_rules(
            SOURCES,
            USER_AGENT,
        )
    )

    if not rules:
        raise RuntimeError(
            "所有上游均未解析出任何规则，拒绝写入空规则"
        )

    rule_converter.write_classical_yaml(
        OUTPUT_FILE,
        build_yaml_header(
            rules,
            stats,
            updated_times,
        ),
        rules,
    )

    print(
        f"\n已写入 {OUTPUT_FILE}，"
        f"共 {len(rules)} 条去重规则"
    )

    print("\n开始转换 AD 规则...")

    rule_converter.emit_folder(
        OUTPUT_DIR,
        OUTPUT_FILE,
        rules,
    )


if __name__ == "__main__":
    main()
