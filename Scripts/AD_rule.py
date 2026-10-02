#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 同目录的规则格式转换工具箱（Scripts/rule_converter.py）
import rule_converter


# ================= 配置 =================

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

# 合法域名校验（含 punycode 的 xn-- 形式）
DOMAIN_RE = re.compile(
    r"^(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


# ================= 拉取 =================

def fetch_text(url: str) -> str:
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

    return raw.decode("utf-8", errors="replace")


# ================= 解析 =================

def parse_abp_line(
    line: str,
) -> Tuple[Optional[str], str]:

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

    if not DOMAIN_RE.match(domain):
        return None, "bad-domain"

    if is_exception:
        return None, "exception"

    return domain, "ok"


def parse_hosts_line(
    line: str,
) -> Tuple[Optional[str], str]:
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

    return domain, "ok"


def parse_domains_line(
    line: str,
) -> Tuple[Optional[str], str]:
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

    return domain, "ok"


# 格式 -> 解析器
PARSERS = {
    "abp": parse_abp_line,
    "hosts": parse_hosts_line,
    "domains": parse_domains_line,
}


# ================= 输出 =================

def build_yaml(
    domains: List[str],
    stats: Dict[str, Dict[str, int]],
) -> str:
    now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    lines = [
        "# AD 聚合广告域名规则",
        "# 由 Scripts/AD_rule.py 自动生成，请勿手动修改",
        f"# 生成时间（UTC）：{now}",
        "# 数据来源：",
    ]

    for name, (url, _kind) in SOURCES.items():
        source_stats = stats[name]

        lines.append(f"#   - {name}: {url}")
        lines.append(
            f"#     原始 {source_stats['lines']} 行，"
            f"提取 {source_stats['ok']} 个域名"
        )

    lines.append(
        f"# 合并去重后域名总数：{len(domains)}"
    )
    lines.append("payload:")

    lines.extend(
        f"  - DOMAIN-SUFFIX,{domain}"
        for domain in domains
    )

    return "\n".join(lines) + "\n"


def main() -> None:
    print("开始拉取聚合广告域名规则...")

    merged: Dict[str, None] = {}
    stats: Dict[str, Dict[str, int]] = {}

    for name, (url, kind) in SOURCES.items():
        print(f"拉取 {name}: {url}")

        text = fetch_text(url)

        parser = PARSERS[kind]

        source_stats: Dict[str, int] = {
            "lines": 0,
            "ok": 0,
        }

        for raw_line in text.splitlines():
            source_stats["lines"] += 1

            domain, reason = parser(
                raw_line
            )

            if domain:
                source_stats["ok"] += 1
                merged.setdefault(domain, None)
            else:
                source_stats[reason] = (
                    source_stats.get(reason, 0) + 1
                )

        if source_stats["ok"] == 0:
            raise RuntimeError(
                f"{name} 未提取到任何域名，"
                f"上游可能已变更格式: {url}"
            )

        stats[name] = source_stats

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
            f"{source_stats['ok']} 个域名 "
            f"({skip_detail})"
        )

    domains = sorted(merged)

    if not domains:
        raise RuntimeError(
            "所有上游均未解析出任何域名，拒绝写入空规则"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_FILE.write_text(
        build_yaml(domains, stats),
        encoding="utf-8",
        newline="\n",
    )

    print(
        f"\n已写入 {OUTPUT_FILE}，"
        f"共 {len(domains)} 个去重域名"
    )


    print("\n开始转换 AD 规则...")

    rule_converter.ensure_mihomo_available()
    rule_converter.prepare_temp_dir()

    cache = rule_converter.make_cache()

    try:
        rule_converter.convert_custom_folder(
            OUTPUT_DIR,
            cache,
        )
    finally:
        rule_converter.cleanup_temp_dir()

    rule_converter.save_cache(cache)


if __name__ == "__main__":
    main()
