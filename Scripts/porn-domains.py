#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Fetch Bon-Appetit/porn-domains and compile it into a stable Mihomo MRS file."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

META_URL = "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/main/meta.json"
OUTPUT_PATH = Path("rule/Clash/Adult/Adult.mrs")
USER_AGENT = "alienwaregf/personal-use porn-domains updater"
TIMEOUT = 60

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


def normalize_domain_line(line: str, line_number: int | None = None) -> str | None:
    """Accept only the upstream's plain Host representation; never reinterpret syntax."""
    line = line.strip().lstrip("\ufeff")

    if not line or line.startswith("#"):
        return None

    context = f"第 {line_number} 行" if line_number is not None else "输入行"

    # Inline comments are not part of a plain Host. Reject instead of guessing.
    if "#" in line:
        raise ValueError(f"{context} 含有不支持的行内注释: {line}")

    # Do not reinterpret any other rule syntax as a Host.
    if line.startswith(("||", "+.", ".")):
        raise ValueError(f"{context} 不是纯 Host 规则，拒绝猜测语义: {line}")

    if not _validate_host(line):
        raise ValueError(f"{context} 不是有效 Host，拒绝猜测语义: {line}")

    # Keep the source spelling exactly (apart from surrounding whitespace/BOM).
    return line


def prepare_domain_text(source_path: Path, output_path: Path) -> int:
    domains: set[str] = set()

    with source_path.open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            domain = normalize_domain_line(line, line_number)
            if domain is not None:
                domains.add(domain)

    if not domains:
        raise RuntimeError("上游 blocklist 没有解析出任何有效域名")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as output:
        for domain in sorted(domains):
            output.write(domain + "\n")

    return len(domains)


def write_readme(readme_path: Path) -> None:
    readme_path.parent.mkdir(parents=True, exist_ok=True)
    readme_path.write_text(
        "# Clash\n\n"
        "domain\n"
        "```text\n"
        "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/Adult/Adult.mrs\n"
        "```\n",
        encoding="utf-8",
    )


def compile_to_mrs(source_text_path: Path, output_path: Path) -> None:
    mihomo = shutil.which("mihomo")
    if not mihomo:
        raise RuntimeError("找不到 mihomo 命令；请先由 GitHub Actions 安装 Mihomo")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="Adult-", suffix=".mrs", dir=output_path.parent, delete=False
    ) as temp_output:
        temp_output_path = Path(temp_output.name)

    try:
        command = [
            mihomo,
            "convert-ruleset",
            "domain",
            "text",
            str(source_text_path),
            str(temp_output_path),
        ]

        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            details = "\n".join(part for part in (stdout, stderr) if part)
            raise RuntimeError(
                f"Mihomo 转换失败，退出码 {result.returncode}"
                + (f"\n{details}" if details else "")
            )

        if not temp_output_path.exists() or temp_output_path.stat().st_size == 0:
            raise RuntimeError("Mihomo 转换完成，但没有生成有效的 MRS 文件")

        os.replace(temp_output_path, output_path)
    finally:
        temp_output_path.unlink(missing_ok=True)


def main() -> None:
    print(f"读取 Bon-Appetit 元数据: {META_URL}")
    meta = json.loads(fetch_text(META_URL))
    blocklist_url = extract_blocklist_url(meta)

    blocklist_meta = meta.get("blocklist", {})
    print(f"当前 blocklist: {blocklist_meta.get('name', blocklist_url)}")
    print(f"更新时间: {blocklist_meta.get('updated', 'unknown')}")
    print(f"下载地址: {blocklist_url}")

    with tempfile.TemporaryDirectory(prefix="Adult-") as temp_dir:
        temp_dir_path = Path(temp_dir)
        source_path = temp_dir_path / "blocklist.txt"
        text_path = temp_dir_path / "adult-domain.txt"

        source_path.write_text(fetch_text(blocklist_url), encoding="utf-8")
        domain_count = prepare_domain_text(source_path, text_path)
        print(f"解析有效域名: {domain_count:,}")

        compile_to_mrs(text_path, OUTPUT_PATH)

    write_readme(OUTPUT_PATH.parent / "README.md")

    size = OUTPUT_PATH.stat().st_size
    print(f"生成完成: {OUTPUT_PATH} ({size:,} bytes)")
    print(f"README 已生成: {OUTPUT_PATH.parent / 'README.md'}")


if __name__ == "__main__":
    main()
