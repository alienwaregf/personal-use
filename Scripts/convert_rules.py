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

# ──────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────
def process_rules():
    if not os.path.exists(DEST_ROOT):
        os.makedirs(DEST_ROOT)

    for root, dirs, files in os.walk(SOURCE_ROOT):
        rel_path = os.path.relpath(root, SOURCE_ROOT)
        target_dir = DEST_ROOT if rel_path == "." else os.path.join(DEST_ROOT, rel_path)

        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        category_name = os.path.basename(root)

        # ── 根目录：只改 README，不做规则处理 ──
        if rel_path == ".":
            if "README.md" in files:
                rewrite_root_readme(
                    os.path.join(root, "README.md"),
                    os.path.join(target_dir, "README.md"),
                )
            continue

        # ── 1. 确定编译源文件（_Classical.yaml 优先，否则用同名 .yaml）──
        classical_yaml = f"{category_name}_Classical.yaml"
        standard_yaml  = f"{category_name}.yaml"
        yaml_for_classical = None          # 将用于编译 classical / domain / ip
        yaml_dest_name     = None          # 要拷贝到目标目录的文件名

        if classical_yaml in files:
            yaml_dest_name     = classical_yaml
            yaml_for_classical = os.path.join(target_dir, classical_yaml)
            shutil.copy2(os.path.join(root, classical_yaml), yaml_for_classical)
        elif standard_yaml in files:
            yaml_dest_name     = standard_yaml
            yaml_for_classical = os.path.join(target_dir, standard_yaml)
            shutil.copy2(os.path.join(root, standard_yaml), yaml_for_classical)

        # ── 2. 从【唯一编译源】提取 domain / IP（不污染其他变体文件）──
        generated_mrs = {}
        if yaml_for_classical and os.path.exists(yaml_for_classical):
            domains, ips = extract_rules_from_file(yaml_for_classical)

            if domains:
                domain_mrs = f"{category_name}_Domain.mrs"
                if compile_ruleset(domains, os.path.join(target_dir, domain_mrs), "domain"):
                    generated_mrs["domain"] = domain_mrs

            if ips:
                ip_mrs = f"{category_name}_IP.mrs"
                if compile_ruleset(ips, os.path.join(target_dir, ip_mrs), "ipcidr"):
                    generated_mrs["ip"] = ip_mrs

        # ── 3. 编译 Classical MRS ──
        if yaml_for_classical and os.path.exists(yaml_for_classical):
            classical_mrs      = f"{category_name}_Classical.mrs"
            classical_mrs_path = os.path.join(target_dir, classical_mrs)
            try:
                result = subprocess.run(
                    ["mihomo", "convert-ruleset", "classical", "yaml",
                     yaml_for_classical, classical_mrs_path],
                    capture_output=True, text=True
                )
                if os.path.exists(classical_mrs_path):
                    generated_mrs["classical"] = classical_mrs
                else:
                    print(f"[WARN] Classical 编译无输出: {result.stderr.strip()}")
            except Exception as e:
                print(f"[ERROR] Classical 编译异常: {e}")

        # ── 4. 重写子目录 README ──
        if "README.md" in files:
            rewrite_sub_readme(
                os.path.join(root, "README.md"),
                os.path.join(target_dir, "README.md"),
                rel_path,
                generated_mrs,
            )


# ──────────────────────────────────────────────
# 从单个文件提取 domain / IP（支持 yaml payload 格式和纯 list 格式）
# ──────────────────────────────────────────────
def extract_rules_from_file(filepath):
    domains, ips = [], []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 去掉 yaml list 前缀 "- " 和引号
            line = re.sub(r"^-\s+", "", line).strip("'\"")
            # 跳过 yaml 结构行（payload:、---）
            if line in ("payload:", "---") or ":" in line.split(",")[0]:
                continue
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
    return list(dict.fromkeys(domains)), list(dict.fromkeys(ips))  # 去重且保序


# ──────────────────────────────────────────────
# 编译单类规则为 MRS
# ──────────────────────────────────────────────
def compile_ruleset(data, output_path, behavior):
    temp_yaml = output_path + ".temp.yaml"
    try:
        with open(temp_yaml, "w", encoding="utf-8") as f:
            yaml.dump(
                {"payload": [str(item) for item in data]},
                f,
                allow_unicode=True,
                default_flow_style=False,
            )
        subprocess.run(
            ["mihomo", "convert-ruleset", behavior, "yaml", temp_yaml, output_path],
            check=True,
            capture_output=True,
        )
        return os.path.exists(output_path)
    except Exception as e:
        print(f"[WARN] compile_ruleset({behavior}) 失败: {e}")
        return False
    finally:
        if os.path.exists(temp_yaml):
            os.remove(temp_yaml)


# ──────────────────────────────────────────────
# 改写根目录 README（把 blackmatrix7 链接全替换为自己的）
# ──────────────────────────────────────────────
def rewrite_root_readme(src_path, dst_path):
    with open(src_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 批量替换已知绝对 URL
    content = content.replace(
        "https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash",
        f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash",
    )
    content = content.replace(
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash",
        f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/rule/Clash",
    )

    # 把仍然是相对路径的 Markdown 链接也改为我的绝对路径
    def root_link_replacer(match):
        text = match.group(1)
        url  = match.group(2).strip()
        if url.startswith("http") or url.startswith("#") or url.startswith("mailto"):
            return match.group(0)
        return f"[{text}](https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash/{url})"

    content = re.sub(r"\[([^\]]+)\]\(([^\)]+)\)", root_link_replacer, content)

    tip = "> [!TIP]\n> 本目录规则已自动转换为 Mihomo Binary MRS 格式与文本 YAML 格式。\n\n"
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(tip + content)


# ──────────────────────────────────────────────
# 改写子目录 README
#
# 逻辑：
#   保留原文档从开头到"## 规则统计"段落末尾的所有内容（含规则统计本身）
#   然后直接跟上我们新生成的 ## Clash 段落
#   原文档中的 ## Clash / ## Surge / ## 使用说明 等后续内容全部丢弃
# ──────────────────────────────────────────────
def rewrite_sub_readme(src_path, dst_path, rel_path, generated_mrs):
    with open(src_path, "r", encoding="utf-8") as f:
        content = f.read()

    url_rel_path = rel_path.replace("\\", "/")

    # ── 截取"保留区"：从开头到第一个我们要删除的 ## 节之前 ──
    # 要删除的节关键字（Clash 本身也删，因为我们要重新写）
    DROP_SECTIONS = r"使用说明|文件区别|配置建议|Clash|Surge|Quantumult X|Loon|Shadowrocket|通用|QuantumultX"
    # 找到第一个要丢弃的 ## 节的位置
    cut_match = re.search(
        rf"^##\s+({DROP_SECTIONS})\b",
        content,
        flags=re.MULTILINE,
    )
    if cut_match:
        clean_content = content[: cut_match.start()].rstrip()
    else:
        # 没有找到任何要丢弃的节 → 保留全部原始内容
        clean_content = content.rstrip()

    # ── 构建新的 ## Clash 段落 ──
    has_domain    = "domain"    in generated_mrs
    has_ip        = "ip"        in generated_mrs
    has_classical = "classical" in generated_mrs
    suffix = " (必须同时使用)" if (has_domain and has_ip) else ""

    clash_block = "## Clash\n\n"
    if has_domain:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        clash_block += f"**Domain 规则{suffix}:**\n\n```text\n{mrs_url}\n```\n\n"
    if has_ip:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        clash_block += f"**IP 规则{suffix}:**\n\n```text\n{mrs_url}\n```\n\n"
    if has_classical:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['classical']}"
        clash_block += f"**Classical 规则 (单独使用):**\n\n```text\n{mrs_url}\n```\n\n"

    tip = "> [!TIP]\n> 本目录下的规则已由上游格式自动转换为 Mihomo Binary MRS 格式。\n\n"
    final_content = tip + clean_content + "\n\n" + clash_block.rstrip() + "\n"

    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(final_content)


if __name__ == "__main__":
    process_rules()
