#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ================= 配置 =================

# 上游规则地址：key 同时用作日志统计标签。
# 注意：easylist 仓库里只有源码碎片，编译好的完整规则发布在
# easylist-downloads.adblockplus.org（这也是 AdGuard/uBO 拉取的地址）。
# 想加更多源（例如 fanboy、adguard），在这里加一行即可。
SOURCES: Dict[str, str] = {
    "easylist": (
        "https://easylist-downloads.adblockplus.org/"
        "easylist.txt"
    ),
    "easyprivacy": (
        "https://easylist-downloads.adblockplus.org/"
        "easyprivacy.txt"
    ),
    "easylistchina": (
        "https://easylist-downloads.adblockplus.org/"
        "easylistchina.txt"
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
            "User-Agent": "personal-use-easylist-sync/1.0",
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
    """
    解析单行 ABP 规则（严格模式）。

    返回 (domain, reason)：domain 非空表示提取到可用广告域名；
    否则 reason 说明跳过原因（comment / cosmetic / exception /
    non-domain-rule / site-scoped / has-options /
    not-caret-terminated / bad-domain）。

    只有 ||domain^ 且零 option 的规则会被接受，该形态与
    Mihomo DOMAIN-SUFFIX 在域名匹配维度严格等价。
    任何带 option、带路径、非 ^ 结尾的规则一律丢弃，不硬转。
    """
    text = line.strip()

    if (
        not text
        or text.startswith("!")
        or text.startswith("[")
    ):
        return None, "comment"

    # 元素隐藏 / 扩展 CSS 等装饰类规则，与域名拦截无关
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

    # 只处理 || 开头的域名锚定规则；
    # |http:// 前缀锚定、正则、纯路径等无法可靠映射为域名
    if not text.startswith("||"):
        return None, "non-domain-rule"

    body = text[2:]
    pattern, _, options = body.partition("$")

    if "domain=" in options:
        return None, "site-scoped"

    # 任何 option 都会改变拦截语意（第三方限定、资源类型限定等），
    # Mihomo 域名规则无法表达，一律丢弃不硬转
    if options:
        return None, "has-options"

    # 严格形态：必须以 ^ 结尾（分隔符语意），不接受路径、
    # 通配符、尾锚定等变体；非法字符由 DOMAIN_RE 统一拦截
    if not pattern.endswith("^"):
        return None, "not-caret-terminated"

    domain = pattern[:-1].lower().rstrip(".")

    if not DOMAIN_RE.match(domain):
        return None, "bad-domain"

    # 白名单例外规则无法表达为 Mihomo 拦截规则，单独计数
    if is_exception:
        return None, "exception"

    return domain, "ok"


# ================= 输出 =================

def build_yaml(
    domains: List[str],
    stats: Dict[str, Dict[str, int]],
) -> str:
    now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    lines = [
        "# EasyList 系广告域名规则（Mihomo 古典格式）",
        "# 由 Scripts/EasyList.py 自动生成，请勿手动修改",
        f"# 生成时间（UTC）：{now}",
        "# 数据来源：",
    ]

    for name, url in SOURCES.items():
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
    print("开始拉取 EasyList 系规则...")

    merged: Dict[str, None] = {}
    stats: Dict[str, Dict[str, int]] = {}

    for name, url in SOURCES.items():
        print(f"拉取 {name}: {url}")

        text = fetch_text(url)

        source_stats: Dict[str, int] = {
            "lines": 0,
            "ok": 0,
        }

        for raw_line in text.splitlines():
            source_stats["lines"] += 1

            domain, reason = parse_abp_line(
                raw_line
            )

            if domain:
                source_stats["ok"] += 1
                merged.setdefault(domain, None)
            else:
                source_stats[reason] = (
                    source_stats.get(reason, 0) + 1
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


if __name__ == "__main__":
    main()
