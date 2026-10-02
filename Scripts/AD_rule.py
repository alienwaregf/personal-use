#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import email.utils
import ipaddress
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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

FETCH_TIMEOUT = 60

DOMAIN_RE = re.compile(
    r"^(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def fetch_text(
    url: str,
) -> Tuple[str, Optional[datetime]]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "personal-use-ad-sync/1.0",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=FETCH_TIMEOUT,
        ) as resp:
            if resp.status != 200:
                raise RuntimeError(
                    f"上游返回 HTTP {resp.status}: {url}"
                )
            raw = resp.read()
    except Exception as exc:
        raise RuntimeError(
            f"拉取上游规则失败: {url}"
        ) from exc

    last_modified: Optional[datetime] = None

    header_value = resp.headers.get(
        "Last-Modified"
    )

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
        raw.decode("utf-8", errors="replace"),
        last_modified,
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

    if DOMAIN_RE.match(domain):

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
    """
    解析 hosts 格式单行：0.0.0.0 domain。

    StevenBlack 的拦截条目均为 0.0.0.0 前缀，一行一个域名。
    返回 (domain, reason)，reason 同 parse_abp_line 的约定。
    """
    text = line.strip()

    if not text or text.startswith("#"):
        return None, "comment"

    parts = text.split()

    if len(parts) < 2 or parts[0] != "0.0.0.0":
        return None, "non-hosts-line"

    domain = parts[1].lower().rstrip(".")

    if not DOMAIN_RE.match(domain):
        return None, "bad-domain"

    return ("DOMAIN-SUFFIX", domain), "ok"


def parse_domains_line(
    line: str,
) -> Tuple[Optional[Tuple[str, str]], str]:
    """
    解析纯域名文件单行：一行一个域名（anti-AD domains）。

    返回 (domain, reason)，reason 同 parse_abp_line 的约定。
    """
    text = line.strip()

    if (
        not text
        or text.startswith("#")
        or text.startswith("!")
    ):
        return None, "comment"

    domain = text.lower().rstrip(".")

    if not DOMAIN_RE.match(domain):
        return None, "bad-domain"

    return ("DOMAIN-SUFFIX", domain), "ok"


# 格式 -> 解析器
PARSERS = {
    "abp": parse_abp_line,
    "hosts": parse_hosts_line,
    "domains": parse_domains_line,
}


# ================= 输出 =================

def build_yaml(
    rules: List[Tuple[str, str]],
    stats: Dict[str, Dict[str, int]],
    updated_times: Dict[str, Optional[datetime]],
) -> str:

    domains = [
        value
        for kind, value in rules
        if kind == "DOMAIN-SUFFIX"
    ]

    ips = [
        value
        for kind, value in rules
        if kind == "IP-CIDR"
    ]
    now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    known_updates = [
        stamp
        for stamp in updated_times.values()
        if stamp is not None
    ]

    if known_updates:
        stamp_line = (
            "# 上游最后更新时间（UTC）："
            + max(known_updates).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )
    else:
        stamp_line = f"# 生成时间（UTC）：{now}"

    lines = [
        "# AD 聚合广告域名规则",
        "# 由 Scripts/AD_rule.py 自动生成，请勿手动修改",
        stamp_line,
        "# 数据来源：",
    ]

    for name, (url, _kind) in SOURCES.items():
        source_stats = stats[name]

        lines.append(f"#   - {name}: {url}")
        lines.append(
            f"#     原始 {source_stats['lines']} 行，"
            f"提取 {source_stats['ok']} 条规则"
        )

    lines.append(
        f"# 合并去重后：域名 {len(domains)} 个，"
        f"IP 规则 {len(ips)} 条"
    )
    lines.append("payload:")

    lines.extend(
        f"  - DOMAIN-SUFFIX,{domain}"
        for domain in domains
    )

    lines.extend(
        f"  - IP-CIDR,{cidr}"
        for cidr in ips
    )

    return "\n".join(lines) + "\n"


def main() -> None:
    print("开始拉取聚合广告域名规则...")

    merged: Set[Tuple[str, str]] = set()
    stats: Dict[str, Dict[str, int]] = {}
    updated_times: Dict[
        str, Optional[datetime]
    ] = {}

    for name, (url, kind) in SOURCES.items():
        print(f"拉取 {name}: {url}")

        text, last_modified = fetch_text(url)

        parser = PARSERS[kind]

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

    rules = sorted(merged)

    if not rules:
        raise RuntimeError(
            "所有上游均未解析出任何规则，拒绝写入空规则"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        build_yaml(rules, stats, updated_times),
        encoding="utf-8",
        newline="\n",
    )

    print(
        f"\n已写入 {OUTPUT_FILE}，"
        f"共 {len(rules)} 条去重规则"
    )


    print("\n开始转换 AD 规则...")

    rule_converter.ensure_mihomo_available()
    rule_converter.prepare_temp_dir()

    cache = rule_converter.make_cache()

    cache_key = (
        cache.key_for([OUTPUT_FILE])
        if cache is not None
        else None
    )

    try:
        rule_converter.convert_prepared_folder(
            OUTPUT_DIR,
            OUTPUT_FILE.name,
            rules,
            cache,
            cache_key,
        )
    finally:
        rule_converter.cleanup_temp_dir()

    rule_converter.save_cache(cache)


if __name__ == "__main__":
    main()
