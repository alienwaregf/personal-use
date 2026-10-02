#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

# 同目录的规则格式转换工具箱（Scripts/rule_converter.py）
import rule_converter


def main() -> None:

    print("开始处理自定义规则...")

    rule_converter.ensure_mihomo_available()

    if not rule_converter.DEST_RULE_DIR.is_dir():
        raise RuntimeError(
            "找不到规则目录: "
            f"{rule_converter.DEST_RULE_DIR}"
        )

    rule_converter.prepare_temp_dir()

    cache = rule_converter.make_cache()

    try:

        for folder in sorted(
            rule_converter.DEST_RULE_DIR.iterdir(),
            key=lambda p: p.name.lower(),
        ):

            if rule_converter.is_custom_rule_folder(
                folder
            ):

                rule_converter.convert_custom_folder(
                    folder,
                    cache,
                )

    finally:
        rule_converter.cleanup_temp_dir()

    rule_converter.save_cache(cache)

    print(
        "\n自定义规则处理完成。"
    )


if __name__ == "__main__":
    main()
