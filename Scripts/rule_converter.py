#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

BEIJING_TZ = timezone(timedelta(hours=8))

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
    "hagezi-normal": (
        "https://raw.githubusercontent.com/"
        "hagezi/dns-blocklists/main/adblock/multi.txt",
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

DISPLAY_NAMES: Dict[str, str] = {
    "easylist": "EasyList",
    "easyprivacy": "EasyPrivacy",
    "easylistchina": "EasyListChina",
    "hagezi-normal": "Dns-BlockLists Normal",
    "stevenblack": "StevenBlack",
    "anti-ad": "anti-AD",
}

OUTPUT_DIR = Path("rule") / "AD"
OUTPUT_FILE = OUTPUT_DIR / "AD.yaml"

USER_AGENT = "personal-use-ad-sync/1.0"


def build_yaml_header(
    rules: List[Tuple[str, str]],
    stats: Dict[str, Dict[str, int]],
    fingerprint: str,
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

    labels = [
        DISPLAY_NAMES[name] for name in SOURCES
    ]

    counts = [
        f"{DISPLAY_NAMES[name]} {stats[name]['ok']}条"
        for name in SOURCES
    ]

    updated = datetime.now(BEIJING_TZ).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    lines = [
        "# AD 聚合广告域名规则",
        "# 数据来源：" + " + ".join(labels),
        "# " + " + ".join(counts),
        f"# 合并去重后：域名 {exact_count + suffix_count} 个，"
        f"IP 规则 {ip_count} 条",
        f"# 上次更新时间：{updated}",
        f"# Hash：{fingerprint}",
    ]

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

    fingerprint = (
        rule_converter.fingerprint_for_rules(
            rules
        )
    )

    if (
        rule_converter.read_stored_hash(
            OUTPUT_FILE
        )
        == fingerprint
        and rule_converter.outputs_complete(
            OUTPUT_DIR,
            rules,
        )
    ):
        print("无更新，跳过：AD")

        return

    rule_converter.write_classical_yaml(
        OUTPUT_FILE,
        build_yaml_header(
            rules,
            stats,
            fingerprint,
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
        use_cache=False,
    )


if __name__ == "__main__":
    main()
