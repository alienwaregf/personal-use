import os
import re
import shutil
import subprocess
import ipaddress
import sys

# ================= 核心配置 =================
SOURCE_CLASH_DIR = os.path.join("source_repo", "rule", "Clash")
DEST_CLASH_DIR = os.path.join("rule", "Clash")
TEMP_DIR = "temp_compile"

MY_REPO_URL = "https://github.com/alienwaregf/personal-use/tree/main/rule/Clash"
RAW_BASE_URL = "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash"

# 只同步这些上游目录。
# 说明：
# - 如果上游目录存在：用上游最新 YAML/README 覆盖并重新编译 MRS。
# - 如果上游目录被删除：你仓库里已有的同名目录不会被删除，会继续保留并尝试用本地 YAML 编译 MRS。
UPSTREAM_INCLUDE_FOLDERS = {
    "Advertising",
    "AppleNews",
    "AppleProxy",
    "AppleTV",
    "AppleMusic",
    "Binance",
    "Claude",
    "Cloudflare",
    "ChinaMax",
    "Download",
    "EA",
    "Google",
    "Gemini",
    "GitHub",
    "HBO",
    "Microsoft",
    "Mail",
    "Netflix",
    "OpenAI",
    "PayPal",
    "Riot",
    "Steam",
    "Spotify",
    "Twitch",
    "Twitter",
    "TikTok",
    "Tmdb",
    "Telegram",
    "YouTube",
}


def strip_yaml_quote(value):
    """去掉 YAML 字符串首尾引号"""
    value = str(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1].strip()
    return value


def parse_payload_rule_line(line):
    """
    解析 payload 里的单条规则。

    输入示例：
      - DOMAIN-SUFFIX,google.com
      - 'IP-CIDR,1.1.1.0/24,no-resolve'

    返回：
      ['DOMAIN-SUFFIX', 'google.com']
      ['IP-CIDR', '1.1.1.0/24', 'no-resolve']
    """
    stripped = line.strip()

    if not stripped.startswith("-"):
        return None

    raw = stripped[1:].strip()
    raw = strip_yaml_quote(raw)

    if not raw or raw.startswith("#"):
        return None

    # 清理简单行内注释，例如：DOMAIN-SUFFIX,example.com # comment
    if " #" in raw:
        raw = raw.split(" #", 1)[0].strip()

    parts = [strip_yaml_quote(p.strip()) for p in raw.split(",")]
    parts = [p for p in parts if p != ""]

    if not parts:
        return None

    return parts


def normalize_domain_rule(parts):
    """
    把 Clash classical 域名规则转换成 Mihomo domain behavior 可用格式。

    转换策略：
      DOMAIN,example.com              -> example.com
      DOMAIN-SUFFIX,example.com       -> .example.com
      DOMAIN-KEYWORD,google           -> *google*
      DOMAIN-WILDCARD,*.example.com   -> *.example.com
      GEOSITE,xxx                     -> 不进入 Domain.mrs
    """
    rule_type = parts[0].upper()

    if len(parts) < 2:
        return None

    value = parts[1].strip()
    value = strip_yaml_quote(value)

    if not value:
        return None

    if rule_type == "DOMAIN":
        return value

    if rule_type == "DOMAIN-SUFFIX":
        value = value.lstrip(".")
        return f".{value}"

    if rule_type == "DOMAIN-KEYWORD":
        return f"*{value}*"

    # DOMAIN-WILDCARD 本身接近 domain behavior 通配写法，直接保留
    if rule_type == "DOMAIN-WILDCARD":
        return value

    # GEOSITE 不是普通 domain-set 内容，不编进 Domain.mrs
    return None


def normalize_ipcidr_rule(parts):
    """
    把 Clash classical IP 规则转换成 Mihomo ipcidr behavior 可用格式。

    只允许：
      IP-CIDR,1.1.1.0/24,no-resolve
      IP-CIDR6,2400:3200::/32,no-resolve

    转换后：
      1.1.1.0/24
      2400:3200::/32

    不允许放入：
      GEOIP,CN
      IP-ASN,xxx
      SRC-IP-CIDR,xxx
    """
    rule_type = parts[0].upper()

    if rule_type not in ("IP-CIDR", "IP-CIDR6"):
        return None

    if len(parts) < 2:
        return None

    cidr = parts[1].strip()
    cidr = strip_yaml_quote(cidr)

    if not cidr:
        return None

    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"跳过非法 CIDR: {','.join(parts)}")
        return None

    return cidr


def split_yaml_payload(filepath):
    """
    提取原始 YAML payload，并转换成 MRS 支持的两种 behavior 内容：

    Domain.mrs:
      behavior: domain
      内容为纯 domain / 通配 domain

    IP.mrs:
      behavior: ipcidr
      内容为纯 CIDR

    注意：
      GEOIP / GEOSITE / IP-ASN / SRC-IP-CIDR 不会被塞进这两个 MRS。
      它们仍保留在原始 Classical YAML 文件里。
    """
    domain_rules = []
    ip_rules = []

    domain_seen = set()
    ip_seen = set()

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            payload_started = False

            for line in f:
                stripped = line.strip()

                if stripped == "payload:":
                    payload_started = True
                    continue

                if not payload_started:
                    continue

                if not stripped.startswith("-"):
                    continue

                parts = parse_payload_rule_line(stripped)

                if not parts:
                    continue

                domain_value = normalize_domain_rule(parts)
                if domain_value:
                    if domain_value not in domain_seen:
                        domain_seen.add(domain_value)
                        domain_rules.append(domain_value)
                    continue

                ip_value = normalize_ipcidr_rule(parts)
                if ip_value:
                    if ip_value not in ip_seen:
                        ip_seen.add(ip_value)
                        ip_rules.append(ip_value)
                    continue

    except Exception as e:
        print(f"读取 {filepath} 时出错: {e}")

    return domain_rules, ip_rules


def write_mrs_source_yaml(path, rules):
    """写入给 mihomo convert-ruleset 使用的临时 YAML"""
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for rule in rules:
            safe_rule = str(rule).replace("'", "''")
            f.write(f"  - '{safe_rule}'\n")


def compile_to_mrs(temp_yaml_path, out_mrs_path, behavior):
    """
    调用 Mihomo 编译 MRS。

    正确格式：
      mihomo convert-ruleset domain yaml xxx.yaml xxx.mrs
      mihomo convert-ruleset ipcidr yaml xxx.yaml xxx.mrs
    """
    os.makedirs(os.path.dirname(out_mrs_path), exist_ok=True)

    cmd = ["mihomo", "convert-ruleset", behavior, "yaml", temp_yaml_path, out_mrs_path]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"编译成功: {out_mrs_path}")
        return True

    except FileNotFoundError:
        print("严重错误: 找不到 mihomo 命令。请确认 GitHub Actions 或本地环境已安装 mihomo。")
        return False

    except subprocess.CalledProcessError as e:
        print(f"编译失败: {out_mrs_path}")
        print(f"命令: {' '.join(cmd)}")

        if e.stdout:
            print("stdout:")
            print(e.stdout)

        if e.stderr:
            print("stderr:")
            print(e.stderr)

        return False


def build_child_readme_replacement(folder_name, classical_filename, has_domain_mrs=True, has_ip_mrs=True):
    """生成子目录 README.md 中 Clash 模块替换内容"""
    cb = "```"
    parts = ["\n"]

    if has_domain_mrs:
        parts.append(
            f"Domain 规则（仅包含域名）\n"
            f"{cb}text\n"
            f"{RAW_BASE_URL}/{folder_name}/{folder_name}_Domain.mrs\n"
            f"{cb}\n\n"
        )

    if has_ip_mrs:
        parts.append(
            f"IP 规则（仅包含IP）\n"
            f"{cb}text\n"
            f"{RAW_BASE_URL}/{folder_name}/{folder_name}_IP.mrs\n"
            f"{cb}\n\n"
        )

    parts.append(
        f"Classical 规则（全量规则）\n"
        f"{cb}text\n"
        f"{RAW_BASE_URL}/{folder_name}/{classical_filename}\n"
        f"{cb}\n\n"
    )

    return "".join(parts)


def modify_readme_clash_section(readme_path, folder_name, classical_filename, has_domain_mrs=True, has_ip_mrs=True):
    """精确定位并替换 README.md 中的 Clash 模块"""
    if not os.path.exists(readme_path):
        return

    with open(readme_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    in_clash_section = False
    clash_level = 0
    clash_processed = False

    replacement_text = build_child_readme_replacement(
        folder_name,
        classical_filename,
        has_domain_mrs=has_domain_mrs,
        has_ip_mrs=has_ip_mrs,
    )

    for line in lines:
        header_match = re.match(r"^(#+)\s*Clash\s*$", line.strip(), re.IGNORECASE)

        if header_match and not clash_processed:
            in_clash_section = True
            clash_level = len(header_match.group(1))
            new_lines.append(line.rstrip() + "\n")
            new_lines.append(replacement_text)
            clash_processed = True
            continue

        if in_clash_section:
            other_header_match = re.match(r"^(#+)\s+(.*)$", line.strip())

            if other_header_match:
                current_level = len(other_header_match.group(1))

                if current_level <= clash_level:
                    in_clash_section = False
                    new_lines.append(line)

            # Clash 模块内原内容跳过
            continue

        new_lines.append(line)

    # 如果 README 里没有 Clash 标题，则在末尾补一个，避免自定义目录 README 没链接
    if not clash_processed:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append("\n## Clash\n")
        new_lines.append(replacement_text)

    with open(readme_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def extract_folder_from_url(url):
    """
    从 README 链接里识别对应的 Clash 子目录名。

    支持：
      ./Google
      Google
      https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash/Google
      https://github.com/alienwaregf/personal-use/tree/main/rule/Clash/Google
    """
    if not url:
        return None

    url = str(url).strip().strip('"\'')

    if (
        url.startswith("#")
        or url.startswith("mailto:")
        or url.startswith("javascript:")
    ):
        return None

    prefixes = [
        MY_REPO_URL + "/",
        RAW_BASE_URL + "/",
        "https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash/",
        "https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/",
    ]

    for prefix in prefixes:
        if url.startswith(prefix):
            rest = url[len(prefix):].strip("/")
            if rest:
                return rest.split("/", 1)[0]
            return None

    if url.startswith("./"):
        rest = url[2:].strip("/")
        if rest:
            return rest.split("/", 1)[0]
        return None

    # 普通相对目录链接，例如 Google 或 Google/
    if not url.startswith("http://") and not url.startswith("https://"):
        rest = url.strip("/")

        if (
            rest
            and not rest.startswith("../")
            and rest != "."
            and "/" not in rest
            and not rest.lower().endswith((".md", ".yaml", ".yml", ".list", ".txt", ".mrs", ".json"))
        ):
            return rest

    return None


def transform_markdown_links_in_text(text, allowed_folders):
    """
    不使用正则，扫描并过滤 Markdown 链接。

    返回：
      new_text: 替换后的文本
      kept_folder_link_count: 保留下来的目录链接数量
      removed_folder_link_count: 删除掉的目录链接数量
    """
    result = []
    i = 0
    kept = 0
    removed = 0
    length = len(text)

    while i < length:
        if text[i] != "[":
            result.append(text[i])
            i += 1
            continue

        label_start = i
        label_end = text.find("]", label_start + 1)

        if label_end == -1 or label_end + 1 >= length or text[label_end + 1] != "(":
            result.append(text[i])
            i += 1
            continue

        url_start = label_end + 2
        url_end = text.find(")", url_start)

        if url_end == -1:
            result.append(text[i])
            i += 1
            continue

        label = text[label_start + 1:label_end]
        url = text[url_start:url_end].strip()
        folder = extract_folder_from_url(url)

        if folder is None:
            # 非 Clash 目录链接，原样保留
            result.append(text[label_start:url_end + 1])
        elif folder in allowed_folders:
            result.append(f"[{label}]({MY_REPO_URL}/{folder})")
            kept += 1
        else:
            # 是 Clash 目录链接，但实际没有保留这个文件夹，删除该链接
            removed += 1

        i = url_end + 1

    return "".join(result), kept, removed


def split_markdown_table_row(line):
    """简单拆分 Markdown 表格行，保留左右边界。"""
    raw = line.rstrip("\n")
    if not raw.strip().startswith("|"):
        return None

    cells = raw.split("|")
    return cells


def is_table_separator_line(line):
    stripped = line.strip()
    if not stripped.startswith("|"):
        return False

    body = stripped.strip("|").strip()
    if not body:
        return False

    for ch in body:
        if ch not in "-:| ":
            return False

    return "-" in body


def process_markdown_table_block(lines, allowed_folders):
    """
    过滤原版 README 里的分类表格。

    逻辑：
      - 表格里的目录链接，只保留实际存在于 rule/Clash 的文件夹；
      - 没有任何保留链接的表格整块删除；
      - 分类标题行保留，但只有在该分类表格内仍有链接时才保留。
    """
    processed = []
    kept_link_total = 0

    for line in lines:
        if is_table_separator_line(line):
            processed.append(line.rstrip("\n"))
            continue

        cells = split_markdown_table_row(line)
        if cells is None:
            continue

        row_kept_links = 0
        row_removed_links = 0
        new_cells = []

        # 第一个和最后一个通常是边界空字符串
        for cell in cells:
            new_cell, kept, removed = transform_markdown_links_in_text(cell, allowed_folders)
            row_kept_links += kept
            row_removed_links += removed
            new_cells.append(new_cell.strip())

        kept_link_total += row_kept_links

        has_any_markdown_link_removed_or_kept = (row_kept_links + row_removed_links) > 0

        if has_any_markdown_link_removed_or_kept and row_kept_links == 0:
            # 这一行原本全是目录链接，但没有一个实际保留，删掉整行
            continue

        new_line = "|".join(new_cells)

        # 确保仍然是表格行
        if not new_line.startswith("|"):
            new_line = "|" + new_line
        if not new_line.endswith("|"):
            new_line = new_line + "|"

        processed.append(new_line)

    if kept_link_total == 0:
        return []

    # 清理只有标题/分隔线但没有链接的异常行，保守保留分类标题
    return [line + "\n" for line in processed]


def filter_root_readme_by_existing_folders(content, allowed_folders):
    """
    根据 rule/Clash 实际存在的目录过滤根 README。

    这会删除原版分类模块里没有实际目录的链接，避免 README 显示未保留的文件夹。
    不再追加“当前保留目录”模块。
    """
    lines = content.splitlines(keepends=True)
    output = []
    i = 0

    while i < len(lines):
        line = lines[i]

        if line.strip().startswith("|"):
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i])
                i += 1

            filtered_block = process_markdown_table_block(block, allowed_folders)
            output.extend(filtered_block)
            continue

        new_line, kept, removed = transform_markdown_links_in_text(line, allowed_folders)

        if removed > 0 and kept == 0 and not new_line.strip():
            i += 1
            continue

        output.append(new_line)
        i += 1

    # 压缩过多空行
    cleaned = []
    blank_count = 0
    for line in output:
        if line.strip() == "":
            blank_count += 1
            if blank_count <= 2:
                cleaned.append(line)
        else:
            blank_count = 0
            cleaned.append(line)

    return "".join(cleaned).strip() + "\n"


def modify_root_readme_links(content):
    """
    只做基础 URL 替换。实际分类过滤在 filter_root_readme_by_existing_folders() 里完成。
    """
    upstream_tree_url = "https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash"
    upstream_blob_url = "https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash"
    upstream_raw_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash"

    content = content.replace(upstream_tree_url, MY_REPO_URL)
    content = content.replace(upstream_blob_url, MY_REPO_URL)
    content = content.replace(upstream_raw_url, RAW_BASE_URL)

    return content

def select_best_yaml(folder_path, folder_name):
    """
    优先选择最全的 Classical YAML。
    如果没有，则选择普通 YAML。
    如果还没有，则兜底选择该目录下第一个 .yaml/.yml 文件，方便自定义目录使用。
    """
    classical_yaml = os.path.join(folder_path, f"{folder_name}_Classical.yaml")
    normal_yaml = os.path.join(folder_path, f"{folder_name}.yaml")

    if os.path.exists(classical_yaml):
        return classical_yaml

    if os.path.exists(normal_yaml):
        return normal_yaml

    yaml_files = []
    try:
        for filename in os.listdir(folder_path):
            lower = filename.lower()
            if lower.endswith((".yaml", ".yml")):
                yaml_files.append(filename)
    except FileNotFoundError:
        return None

    if yaml_files:
        yaml_files.sort()
        return os.path.join(folder_path, yaml_files[0])

    return None


def list_current_upstream_folders():
    """列出当前 blackmatrix7 上游 Clash 目录中的所有文件夹名"""
    if not os.path.exists(SOURCE_CLASH_DIR):
        return set()

    return {
        item
        for item in os.listdir(SOURCE_CLASH_DIR)
        if os.path.isdir(os.path.join(SOURCE_CLASH_DIR, item))
    }


def prepare_dest_clash_dir():
    """
    准备目标目录。

    关键逻辑：
      1. 不再删除整个 rule/Clash。
      2. 当前上游存在、但不在 UPSTREAM_INCLUDE_FOLDERS 里的目录，会被删除。
         这用于清掉以前全量同步留下来的上游目录。
      3. 不在当前上游里的目录，视为你自己的自定义目录，保留。
      4. 在 UPSTREAM_INCLUDE_FOLDERS 里的目录，无论上游是否还存在，都保留。
    """
    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    current_upstream_folders = list_current_upstream_folders()

    for item in sorted(os.listdir(DEST_CLASH_DIR)):
        item_path = os.path.join(DEST_CLASH_DIR, item)

        if not os.path.isdir(item_path):
            continue

        if item in UPSTREAM_INCLUDE_FOLDERS:
            print(f"保留白名单目录: {item}")
            continue

        if item in current_upstream_folders:
            print(f"删除非白名单上游目录: {item}")
            shutil.rmtree(item_path, ignore_errors=True)
            continue

        print(f"保留自定义目录: {item}")


def copy_upstream_folder_files(folder_name):
    """
    同步指定上游目录。

    如果上游目录存在：
      - 清空目标同名目录；
      - 只复制最优 YAML；
      - 如果有 README.md，也复制并改写 Clash 模块。
    如果上游目录不存在：
      - 不删除本地同名目录；
      - 后续会按本地目录继续编译。
    """
    source_folder = os.path.join(SOURCE_CLASH_DIR, folder_name)
    dest_folder = os.path.join(DEST_CLASH_DIR, folder_name)

    if not os.path.isdir(source_folder):
        print(f"上游目录不存在，保留本地目录不删除: {folder_name}")
        return False

    target_yaml = select_best_yaml(source_folder, folder_name)

    if not target_yaml:
        print(f"上游目录没有可用 YAML，跳过同步但不删除本地目录: {folder_name}")
        return False

    if os.path.exists(dest_folder):
        shutil.rmtree(dest_folder)

    os.makedirs(dest_folder, exist_ok=True)

    target_filename = os.path.basename(target_yaml)
    shutil.copy2(target_yaml, os.path.join(dest_folder, target_filename))

    src_readme = os.path.join(source_folder, "README.md")
    dest_readme = os.path.join(dest_folder, "README.md")

    if os.path.exists(src_readme):
        shutil.copy2(src_readme, dest_readme)

    return True


def compile_folder(folder_name, folder_path, modify_readme=True):
    """编译某个目录中的 YAML 为 Domain/IP MRS"""
    target_yaml = select_best_yaml(folder_path, folder_name)

    if not target_yaml:
        print(f"跳过目录：{folder_name} 没有可用 YAML")
        return {
            "processed": False,
            "domain": False,
            "ip": False,
            "failures": 0,
        }

    print(f"\n正在处理目录: {folder_name}")

    target_filename = os.path.basename(target_yaml)
    domain_rules, ip_rules = split_yaml_payload(target_yaml)

    print(f"Domain 规则数量: {len(domain_rules)}")
    print(f"IP CIDR 规则数量: {len(ip_rules)}")

    domain_mrs_path = os.path.join(folder_path, f"{folder_name}_Domain.mrs")
    ip_mrs_path = os.path.join(folder_path, f"{folder_name}_IP.mrs")

    has_domain_mrs = False
    has_ip_mrs = False
    failures = 0

    # Domain MRS
    if domain_rules:
        temp_domain_yaml = os.path.join(TEMP_DIR, f"{folder_name}_temp_domain.yaml")
        write_mrs_source_yaml(temp_domain_yaml, domain_rules)

        if compile_to_mrs(temp_domain_yaml, domain_mrs_path, "domain"):
            has_domain_mrs = True
        else:
            failures += 1
    else:
        print(f"跳过 Domain.mrs：{folder_name} 没有可转换的 Domain 规则")

    # IP MRS
    if ip_rules:
        temp_ip_yaml = os.path.join(TEMP_DIR, f"{folder_name}_temp_ip.yaml")
        write_mrs_source_yaml(temp_ip_yaml, ip_rules)

        if compile_to_mrs(temp_ip_yaml, ip_mrs_path, "ipcidr"):
            has_ip_mrs = True
        else:
            failures += 1
    else:
        print(f"跳过 IP.mrs：{folder_name} 没有可转换的 IP-CIDR/IP-CIDR6 规则")

    # 修改 README
    if modify_readme:
        readme_path = os.path.join(folder_path, "README.md")

        if os.path.exists(readme_path):
            modify_readme_clash_section(
                readme_path,
                folder_name,
                target_filename,
                has_domain_mrs=has_domain_mrs,
                has_ip_mrs=has_ip_mrs,
            )

    return {
        "processed": True,
        "domain": has_domain_mrs,
        "ip": has_ip_mrs,
        "failures": failures,
    }



def add_root_readme_tip(content):
    """
    在 Clash 根目录 README.md 顶部添加自用提示。

    该提示每次重新生成 README 时都会自动写入；
    如果原内容里已经有同样提示，会先清理旧提示，避免重复。
    """
    tip = (
        "> [!IMPORTANT]\n"
        "> 所有内容均来自 [blackmatrix7大佬](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash) 的二次编译，仅自用，勿传播，谢谢！\n\n"
    )

    old_tip_pattern = (
        "> [!IMPORTANT]\n"
        "> 所有内容均来自 [blackmatrix7大佬](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash) 的二次编译，仅自用，勿传播，谢谢！\n\n"
    )

    content = content.replace(old_tip_pattern, "")

    return tip + content.lstrip()

def write_root_readme():
    """
    写入 Clash 根目录 README。

    逻辑：
      1. 沿用 blackmatrix7 原版 README 的分类结构；
      2. 只保留 rule/Clash 实际存在的目录链接；
      3. 链接统一改成你的 personal-use 仓库链接；
      4. 不再追加“当前保留目录”模块。
    """
    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    src_root_readme = os.path.join(SOURCE_CLASH_DIR, "README.md")
    dest_root_readme = os.path.join(DEST_CLASH_DIR, "README.md")

    existing_folders = {
        item
        for item in os.listdir(DEST_CLASH_DIR)
        if os.path.isdir(os.path.join(DEST_CLASH_DIR, item))
    }

    if os.path.exists(src_root_readme):
        with open(src_root_readme, "r", encoding="utf-8") as f:
            root_content = f.read()

        root_content = modify_root_readme_links(root_content)
        root_content = filter_root_readme_by_existing_folders(root_content, existing_folders)
    else:
        root_content = "# Clash\n\n"
        root_content += "## 分类\n\n"
        for folder in sorted(existing_folders):
            root_content += f"- [{folder}]({MY_REPO_URL}/{folder})\n"

    root_content = add_root_readme_tip(root_content)

    with open(dest_root_readme, "w", encoding="utf-8") as f:
        f.write(root_content)

def clean_workspace_garbage():
    """
    清理 GitHub Actions 工作区里的临时垃圾，防止被 git add 误提交。

    注意：
      不删除 rule/Clash，因为这是最终产物。
      source_repo 是上游临时仓库，脚本处理完后可以删除。
    """
    paths_to_remove = [
        TEMP_DIR,
        "source_repo",
        "__pycache__",
        os.path.join("Scripts", "__pycache__"),
        "mihomo",
        "mihomo.gz",
    ]

    for path in paths_to_remove:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            print(f"已清理目录: {path}")
        elif os.path.isfile(path):
            try:
                os.remove(path)
                print(f"已清理文件: {path}")
            except FileNotFoundError:
                pass

    for root, dirs, files in os.walk("."):
        # 避免进入 .git，防止误操作 Git 内部文件
        if ".git" in dirs:
            dirs.remove(".git")

        for filename in files:
            if filename == ".DS_Store":
                file_path = os.path.join(root, filename)
                try:
                    os.remove(file_path)
                    print(f"已清理文件: {file_path}")
                except FileNotFoundError:
                    pass

        for dirname in list(dirs):
            if dirname == "__pycache__":
                dir_path = os.path.join(root, dirname)
                shutil.rmtree(dir_path, ignore_errors=True)
                print(f"已清理目录: {dir_path}")
                dirs.remove(dirname)


def main():
    print("开始执行 Clash 规则拆分与 MRS 编译任务...")
    print("模式：上游白名单同步 + 本地自定义目录保留")

    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

    os.makedirs(TEMP_DIR, exist_ok=True)

    if not os.path.exists(SOURCE_CLASH_DIR):
        print(f"严重错误: 找不到上游源码目录 {SOURCE_CLASH_DIR}")
        sys.exit(1)

    prepare_dest_clash_dir()

    print("\n开始同步白名单上游目录...")

    for item in sorted(UPSTREAM_INCLUDE_FOLDERS):
        copy_upstream_folder_files(item)

    print("\n开始拆分并编译规则...")

    total_folders = 0
    compiled_domain = 0
    compiled_ip = 0
    skipped_no_yaml = 0
    compile_failures = 0

    # 编译所有最终保留下来的目录：
    # 1. 白名单上游目录；
    # 2. 上游已删除但你本地保留的白名单目录；
    # 3. 你自己的自定义目录。
    for item in sorted(os.listdir(DEST_CLASH_DIR)):
        folder_path = os.path.join(DEST_CLASH_DIR, item)

        if not os.path.isdir(folder_path):
            continue

        result = compile_folder(item, folder_path, modify_readme=True)

        if not result["processed"]:
            skipped_no_yaml += 1
            continue

        total_folders += 1

        if result["domain"]:
            compiled_domain += 1

        if result["ip"]:
            compiled_ip += 1

        compile_failures += result["failures"]

    write_root_readme()

    print("\n清理临时编译环境...")

    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

    print("\n转换与编译全部完成！")
    print(f"处理目录数量: {total_folders}")
    print(f"成功编译 Domain.mrs 数量: {compiled_domain}")
    print(f"成功编译 IP.mrs 数量: {compiled_ip}")
    print(f"跳过无 YAML 目录数量: {skipped_no_yaml}")

    if compile_failures > 0:
        print(f"严重错误: 有 {compile_failures} 个 MRS 文件编译失败。")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    finally:
        print("\n清理工作区临时文件...")
        clean_workspace_garbage()
