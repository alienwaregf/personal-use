#!/usr/bin/env python3
"""一次性脚本：删除 rule/ 下全部旧命名 *_Domain.mrs，跑完即删本文件。"""

from pathlib import Path


def main() -> None:
    targets = sorted(
        Path("rule").rglob("*_Domain.mrs")
    )

    for path in targets:
        path.unlink()
        print(f"已删除: {path}")

    print(f"共删除 {len(targets)} 个文件")


if __name__ == "__main__":
    main()
