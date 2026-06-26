import os
import re
import shutil
import subprocess
import yaml

# 配置信息
GITHUB_USER = "alienwaregf"
GITHUB_REPO = "personal-use"
SOURCE_ROOT = "source_repo/rule/Clash"
DEST_ROOT = "rule/Clash"
BASE_RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/rule/Clash"

# ==================== 需要删除的章节标题（精确匹配 ## 后的文字） ====================
SECTIONS_TO_REMOVE = {
    "使用说明",
    "配置建议",
    "文件区别",
    "Clash",
    "Surge",
    "Quantumult X",
    "Loon",
    "Shadowrocket",
    "通用",
    "OpenClash",
    "Stash",
    "Egern",
    "sing-box",
    "AdGuard Home",
    "AdGuard",
    "其他",
}


def process_rules():
    if not os.path.exists(DEST_ROOT):
        os.makedirs(DEST_ROOT)

    for root, dirs, files in os.walk(SOURCE_ROOT):
        rel_path = os.path.relpath(root, SOURCE_ROOT)
        target_dir = DEST_ROOT if rel_path == "." else os.path.join(DEST_ROOT, rel_path)

        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        category_name = os.path.basename(root)

        # ==================== 特殊处理：根目录 ====================
        if rel_path == ".":
            if "README.md" in files:
                rewrite_root_readme(
                    os.path.join(root, "README.md"),
                    os.path.join(target_dir, "README.md")
                )
            continue

        # ==================== 1. 确定要保留的 YAML 文件 ====================
        # _Classical.yaml 优先（最全），fallback 到普通 .yaml
        classical_yaml = f"{category_name}_Classical.yaml"
        standard_yaml  = f"{category_name}.yaml"
        kept_yaml_dst  = None

        if classical_yaml in files:
            src = os.path.join(root, classical_yaml)
            dst = os.path.join(target_dir, classical_yaml)
            shutil.copy2(src, dst)
            kept_yaml_dst = dst
        elif standard_yaml in files:
            src = os.path.join(root, standard_yaml)
            dst = os.path.join(target_dir, standard_yaml)
            shutil.copy2(src, dst)
            kept_yaml_dst = dst

        # ==================== 2. 提取 Domain / IP，分别编译 MRS ====================
        domains, ips = extract_rules(root, files)
        generated_mrs = {}

        if domains:
            domain_mrs = f"{category_name}_Domain.mrs"
            if compile_ruleset(domains, os.path.join(target_dir, domain_mrs), "domain"):
                generated_mrs["domain"] = domain_mrs

        if ips:
            ip_mrs = f"{category_name}_IP.mrs"
            if compile_ruleset(ips, os.path.join(target_dir, ip_mrs), "ipcidr"):
                generated_mrs["ip"] = ip_mrs

        # ==================== 3. 编译 Classical MRS ====================
        if kept_yaml_dst and os.path.exists(kept_yaml_dst):
            classical_mrs      = f"{category_name}_Classical.mrs"
            classical_mrs_path = os.path.join(target_dir, classical_mrs)
            try:
                result = subprocess.run(
                    ["mihomo", "convert-ruleset", "classical", "yaml",
                     kept_yaml_dst, classical_mrs_path],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    print(f"[WARN] Classical MRS ({category_name}): {result.stderr.strip()}")
                if os.path.exists(classical_mrs_path):
                    generated_mrs["classical"] = classical_mrs
            except Exception as e:
                print(f"[ERROR] Classical MRS ({category_name}): {e}")

        # ==================== 4. 重写子目录 README ====================
        if "README.md" in files:
            rewrite_sub_readme(
                os.path.join(root, "README.md"),
                os.path.join(target_dir, "README.md"),
                rel_path,
                generated_mrs
            )


# ==================== 工具函数 ====================

def extract_rules(root, files):
    """
    从目录下所有 .yaml / .list 文件里提取 DOMAIN / IP 条目。
    支持：
      - YAML payload 格式：  - DOMAIN-SUFFIX,google.com
      - 纯文本 list 格式：   DOMAIN-SUFFIX,google.com
    """
    domains, ips = [], []
    for file in files:
        if not file.endswith((".yaml", ".list")):
            continue
        filepath = os.path.join(root, file)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 去掉 YAML list 前缀 "- " 以及引号
                    line = re.sub(r"^-\s*", "", line).replace("'", "").replace('"', "")
                    parts = line.split(",")
                    if len(parts) < 2:
                        continue
                    rule_type = parts[0].strip().upper()
                    value     = parts[1].strip()
                    if not value:
                        continue

                    if rule_type == "DOMAIN-SUFFIX":
                        domains.append("+." + value)
                    elif rule_type == "DOMAIN":
                        domains.append(value)
                    elif rule_type in ("IP-CIDR", "IP-CIDR6"):
                        ips.append(value)
        except Exception as e:
            print(f"[WARN] 读取 {filepath} 失败: {e}")

    # 去重保序
    return list(dict.fromkeys(domains)), list(dict.fromkeys(ips))


def compile_ruleset(data, output_path, behavior):
    """把 domain 或 ipcidr 列表写成临时 YAML，用 mihomo 编译为 .mrs"""
    temp_yaml = output_path + ".tmp.yaml"
    try:
        with open(temp_yaml, "w", encoding="utf-8") as f:
            yaml.dump({"payload": data}, f, allow_unicode=True)
        result = subprocess.run(
            ["mihomo", "convert-ruleset", behavior, "yaml", temp_yaml, output_path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[WARN] compile_ruleset ({behavior}): {result.stderr.strip()}")
        return os.path.exists(output_path)
    except Exception as e:
        print(f"[ERROR] compile_ruleset ({behavior}): {e}")
        return False
    finally:
        if os.path.exists(temp_yaml):
            os.remove(temp_yaml)


# ==================== README 处理 ====================

def rewrite_root_readme(src_path, dst_path):
    """
    根目录 README：把 blackmatrix7 的链接全部替换为我的，顶部加 TIP。
    """
    with open(src_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = content.replace(
        "https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash",
        f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash"
    )
    content = content.replace(
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash",
        f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/rule/Clash"
    )

    def root_link_replacer(match):
        text = match.group(1)
        url  = match.group(2).strip()
        if url.startswith("http") or url.startswith("#") or url.startswith("mailto"):
            return match.group(0)
        return (
            f"[{text}](https://github.com/{GITHUB_USER}/{GITHUB_REPO}"
            f"/tree/main/rule/Clash/{url})"
        )

    content = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", root_link_replacer, content)

    tip = "> [!TIP]\n> 本目录规则已自动转换为 Mihomo Binary MRS 格式与文本 YAML 格式。\n\n"
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(tip + content)


def parse_readme_sections(content):
    """
    把 README 按 ## 章节拆分，返回有序列表：
      [{"title": None, "raw": "前言..."}, {"title": "规则统计", "raw": "## 规则统计\n..."}, ...]
    title=None 表示第一个 ## 之前的前言部分。
    只切割二级标题（## ），不切割 ### 及更深层。
    """
    pattern   = re.compile(r"^(## .+)$", re.MULTILINE)
    positions = [m.start() for m in pattern.finditer(content)]
    sections  = []

    if not positions:
        sections.append({"title": None, "raw": content})
        return sections

    # 前言
    preamble = content[: positions[0]]
    if preamble.strip():
        sections.append({"title": None, "raw": preamble})

    for i, pos in enumerate(positions):
        end   = positions[i + 1] if i + 1 < len(positions) else len(content)
        chunk = content[pos:end]
        title = chunk.splitlines()[0].lstrip("#").strip()
        sections.append({"title": title, "raw": chunk})

    return sections


def rewrite_sub_readme(src_path, dst_path, rel_path, generated_mrs):
    """
    子目录 README 重写：
    - 删除 SECTIONS_TO_REMOVE 中的章节
    - 保留其余章节（前言、规则统计、子规则、排除规则、数据来源等）
    - 末尾追加我们自己的 ## Clash 章节（含三个 MRS 链接）
    """
    with open(src_path, "r", encoding="utf-8") as f:
        content = f.read()

    url_rel_path = rel_path.replace("\\", "/")
    sections     = parse_readme_sections(content)

    kept_parts = []
    for sec in sections:
        title = sec["title"]
        if title is None:
            kept_parts.append(sec["raw"])   # 前言始终保留
            continue
        if title in SECTIONS_TO_REMOVE:
            continue                         # 删除指定章节
        kept_parts.append(sec["raw"])        # 其余章节全部保留

    clean_content = "".join(kept_parts).rstrip()

    # ==================== 构建 ## Clash 章节 ====================
    has_domain    = "domain"    in generated_mrs
    has_ip        = "ip"        in generated_mrs
    has_classical = "classical" in generated_mrs

    pair_suffix = " (必须同时使用)" if (has_domain and has_ip) else ""

    clash_block = "## Clash\n\n"

    if has_domain:
        url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        clash_block += f"**Domain 规则{pair_suffix}:**\n\n```text\n{url}\n```\n\n"

    if has_ip:
        url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        clash_block += f"**IP 规则{pair_suffix}:**\n\n```text\n{url}\n```\n\n"

    if has_classical:
        url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['classical']}"
        clash_block += f"**Classical 规则 (单独使用):**\n\n```text\n{url}\n```\n\n"

    if not (has_domain or has_ip or has_classical):
        clash_block += "_（本规则集暂无可用 MRS 文件）_\n\n"

    # ==================== 拼接 ====================
    tip   = "> [!TIP]\n> 本目录下的规则已由上游格式自动转换为 Mihomo Binary MRS 格式。\n\n"
    final = tip + clean_content + "\n\n" + clash_block.rstrip() + "\n"

    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(final)


if __name__ == "__main__":
    process_rules()
