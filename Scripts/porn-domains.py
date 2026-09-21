````python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Fetch Bon-Appetit/porn-domains and prepare the Adult source rules."""

from __future__ import annotations

import ipaddress
import json
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

META_URL = "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/main/meta.json"
ADULT_YAML_PATH = Path("rule/Adult/Adult.yaml")
ADULT_README_PATH = Path("rule/Adult/README.md")
USER_AGENT = "alienwaregf/personal-use porn-domains updater"
TIMEOUT = 60
COMPRESSION_THRESHOLD = 2

DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8-sig")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"下载失败: {url}\n{exc}") from exc


def extract_blocklist_url(meta: dict) -> str:
    try:
        url = str(meta["blocklist"]["raw_url"]).strip()
    except (KeyError, TypeError) as exc:
        raise ValueError("meta.json 缺少 blocklist.raw_url") from exc

    if not url.startswith("https://"):
        raise ValueError(f"blocklist.raw_url 不是 HTTPS 地址: {url}")

    return url


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


def parent_suffixes(host: str) -> list[str]:
    labels = host.split(".")

    if len(labels) < 3:
        return []

    return [
        ".".join(labels[i:])
        for i in range(0, len(labels) - 2)
    ]


def compress_domains(domains: set[str]) -> set[str]:
    suffix_members: dict[str, set[str]] = defaultdict(set)

    for domain in domains:
        for suffix in parent_suffixes(domain):
            suffix_members[suffix].add(domain)

    candidates = [
        (suffix, members)
        for suffix, members in suffix_members.items()
        if len(members) >= COMPRESSION_THRESHOLD
    ]

    candidates.sort(
        key=lambda item: len(item[0].split(".")),
        reverse=True,
    )

    remaining = set(domains)
    output: set[str] = set()
    compressed = 0

    for suffix, _ in candidates:
        members = {
            domain
            for domain in remaining
            if domain == suffix or domain.endswith("." + suffix)
        }

        if len(members) < COMPRESSION_THRESHOLD:
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


def prepare_domain_text(source_path: Path, output_path: Path) -> int:
    domains: set[str] = set()

    with source_path.open("r", encoding="utf-8-sig") as source:
        for line in source:
            domain = normalize_domain_line(line)

            if domain is not None:
                domains.add(domain)

    if not domains:
        raise RuntimeError("上游 blocklist 没有解析出任何有效域名")

    compressed_domains = compress_domains(domains)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as output:
        for domain in sorted(compressed_domains):
            output.write(domain + "\n")

    return len(compressed_domains)


def write_adult_yaml(output_path: Path, domains: set[str]) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as output:
        output.write("payload:\n")

        for domain in sorted(domains):
            if domain.startswith("+."):
                rule_type = "DOMAIN-SUFFIX"
                value = domain[2:].lstrip(".")
            else:
                rule_type = "DOMAIN"
                value = domain

            output.write(f"  - {rule_type},{value}\n")

    return len(domains)


def write_readme(readme_path: Path) -> None:
    readme_path.parent.mkdir(parents=True, exist_ok=True)

    readme_path.write_text(
        "# Clash\n\n"
        "domain\n"
        "```text\n"
        "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Adult/Adult_Domain.mrs\n"
        "```\n",
        encoding="utf-8",
    )


def main() -> None:
    print(f"读取 Bon-Appetit 元数据: {META_URL}")

    meta = json.loads(fetch_text(META_URL))
    blocklist_url = extract_blocklist_url(meta)

    blocklist_meta = meta.get("blocklist", {})

    print(
        f"当前 blocklist: "
        f"{blocklist_meta.get('name', blocklist_url)}"
    )
    print(
        f"更新时间: "
        f"{blocklist_meta.get('updated', 'unknown')}"
    )
    print(f"下载地址: {blocklist_url}")

    with tempfile.TemporaryDirectory(prefix="Adult-") as temp_dir:
        temp_dir_path = Path(temp_dir)
        source_path = temp_dir_path / "blocklist.txt"
        text_path = temp_dir_path / "adult-domain.txt"

        source_path.write_text(
            fetch_text(blocklist_url),
            encoding="utf-8",
        )

        domain_count = prepare_domain_text(
            source_path,
            text_path,
        )

        print(
            f"最终 Domain 规则数量: "
            f"{domain_count:,}"
        )

        domains = {
            line.strip()
            for line in text_path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        }

        yaml_count = write_adult_yaml(
            ADULT_YAML_PATH,
            domains,
        )

        print(
            f"Adult.yaml 已保存: "
            f"{ADULT_YAML_PATH} "
            f"({yaml_count:,} 条规则)"
        )

    write_readme(ADULT_README_PATH)

    print(
        "Adult 源规则准备完成；"
        "MRS 将由 convert_rules.py 统一生成。"
    )
    print(
        f"Adult.yaml 已保存: "
        f"{ADULT_YAML_PATH}"
    )
    print(
        f"README 已生成: "
        f"{ADULT_README_PATH}"
    )


if __name__ == "__main__":
    main()
````
