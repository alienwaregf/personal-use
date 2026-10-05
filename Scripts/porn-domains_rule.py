#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Fetch Bon-Appetit/porn-domains and prepare the Adult source rules."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
import re
from pathlib import Path

import rule_converter

META_URL = "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/main/meta.json"
ADULT_YAML_PATH = Path("rule/Adult/Adult.yaml")
USER_AGENT = "alienwaregf/personal-use porn-domains_rule updater"

MAJOR_DOMAINS = {
    "51cg1.com",
    "8se.me",
    "91cg.com",
    "91cg1.com",
    "91porn.com",
    "91porna.com",
    "91porny.com",
    "beeg.com",
    "camsoda.ai",
    "candy.ai",
    "chaturbate.com",
    "chigua.com",
    "eporner.com",
    "heiliao.com",
    "hqporner.com",
    "lovescape.com",
    "mrds.com",
    "ourdream.ai",
    "pornhub.com",
    "promptchan.com",
    "redgifs.com",
    "redtube.com",
    "secrets.ai",
    "seduced.com",
    "spankbang.com",
    "stripchat.com",
    "t66y.com",
    "theporndude.com",
    "thisvid.com",
    "ttrgw.com",
    "tube8.com",
    "xhamster.com",
    "xhamster19.com",
    "xhamster2.com",
    "xhamsterlive.com",
    "xnxx.com",
    "xnxx.tv",
    "xvideos.com",
    "xvideos.es",
    "xvideos2.com",
    "youporn.com",
    "youjizz.com",
}

DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

def extract_blocklist(
    meta: dict,
) -> tuple[str, str]:
    try:
        blocklist = meta["blocklist"]
        url = str(blocklist["raw_url"]).strip()
        updated_raw = str(blocklist["updated"]).strip()
    except (KeyError, TypeError) as exc:
        raise ValueError(
            "meta.json 缺少 blocklist.raw_url 或 blocklist.updated"
        ) from exc

    if not url.startswith("https://"):
        raise ValueError(f"blocklist.raw_url 不是 HTTPS 地址: {url}")

    try:
        updated = datetime.strptime(
            updated_raw,
            "%Y-%m-%dT%H:%M:%SZ",
        )
    except ValueError as exc:
        raise ValueError(
            f"blocklist.updated 格式异常: {updated_raw}"
        ) from exc

    return url, updated.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

def _validate_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False

    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass

    labels = host.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return False

        if not DOMAIN_LABEL_RE.fullmatch(label):
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

    return True

def normalize_domain_line(line: str) -> str | None:
    line = line.strip().lstrip("\ufeff")

    if not line or line.startswith("#"):
        return None

    if "#" in line or line.startswith(("||", "+.", ".")):
        return None

    host = line.lower()

    if not _validate_host(host):
        return None

    return host

def extract_major_domains(
    domains: set[str],
) -> tuple[set[str], set[str]]:
    remaining = set(domains)
    major_rules = {
        f"+.{domain}"
        for domain in MAJOR_DOMAINS
    }

    filtered = 0

    for major in MAJOR_DOMAINS:
        matched = {
            domain
            for domain in remaining
            if (
                domain == major
                or domain.endswith("." + major)
            )
        }

        filtered += len(matched)
        remaining.difference_update(matched)

    print(
        f"大型平台固定: {len(MAJOR_DOMAINS):,} 个 "
        f"DOMAIN-SUFFIX；"
        f"过滤原始域名: {filtered:,} 个"
    )

    return remaining, major_rules

def prepare_domains(text: str) -> set[str]:
    domains: set[str] = set()

    for line in text.splitlines():
        domain = normalize_domain_line(line)

        if domain is not None:
            domains.add(domain)

    if not domains:
        raise RuntimeError("上游 blocklist 没有解析出任何有效域名")

    remaining_domains, major_rules = extract_major_domains(
        domains
    )

    compressed_domains = rule_converter.compress_domains(
        remaining_domains
    )

    return major_rules | compressed_domains

def main() -> None:
    print(
        f"读取 Bon-Appetit 元数据: {META_URL}"
    )

    meta = json.loads(
        rule_converter.fetch_text(
            META_URL,
            USER_AGENT,
            encoding="utf-8-sig",
        )[0]
    )

    blocklist_url, upstream_updated = (
        extract_blocklist(meta)
    )

    blocklist_meta = meta.get(
        "blocklist",
        {},
    )

    print(
        f"当前 blocklist: "
        f"{blocklist_meta.get('name', blocklist_url)}"
    )

    print(
        f"更新时间: "
        f"{blocklist_meta.get('updated', 'unknown')}"
    )

    print(
        f"下载地址: {blocklist_url}"
    )

    blocklist_text, _last_modified = (
        rule_converter.fetch_text(
            blocklist_url,
            USER_AGENT,
            encoding="utf-8-sig",
        )
    )

    domains = prepare_domains(
        blocklist_text
    )

    print(
        f"最终 Domain 规则数量: "
        f"{len(domains):,}"
    )

    adult_rules = rule_converter.domains_to_rules(
        domains
    )

    header_lines = [
        "# Adult 域名规则",
        "# 由 Scripts/porn-domains_rule.py 自动生成，请勿手动修改",
        f"# 上游最后更新时间（UTC）：{upstream_updated}",
        "# 数据来源：https://github.com/Bon-Appetit/porn-domains",
    ]

    rule_converter.write_classical_yaml(
        ADULT_YAML_PATH,
        header_lines,
        adult_rules,
    )

    print(
        f"Adult.yaml 已保存: "
        f"{ADULT_YAML_PATH} "
        f"({len(adult_rules):,} 条规则)"
    )

    print("\n开始转换 Adult 规则...")

    rule_converter.emit_folder(
        ADULT_YAML_PATH.parent,
        ADULT_YAML_PATH,
        adult_rules,
    )

if __name__ == "__main__":
    main()
