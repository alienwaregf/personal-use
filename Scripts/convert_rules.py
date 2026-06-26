import os
import re
import shutil
import subprocess
import ipaddress

# ================= 核心配置 =================
SOURCE_CLASH_DIR = os.path.join("source_repo", "rule", "Clash")
DEST_CLASH_DIR = os.path.join("rule", "Clash")
TEMP_DIR = "temp_compile"

MY_REPO_URL = "https://github.com/alienwaregf/personal-use/tree/main/rule/Clash"
RAW_BASE_URL = "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash"


def strip_yaml_quote(value):
    """去掉 YAML 字符串首尾引号"""
    value = value.strip()
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

    parts = [p.strip() for p in raw.split(",")]
    parts = [p for p in parts if p != ""]

    if not parts:
        return None

    return parts


def normalize_domain_rule(parts):
    """
    把 Clash classical 域名规则转换成 Mihomo domain behavior 可用格式。

    Mihomo domain 示例：
      payload:
        - '.blogger.com'
        - '*.*.microsoft.com'
        - 'books.itunes.apple.com'

    转换策略：
      DOMAIN,example.com              -> example.com
      DOMAIN-SUFFIX,example.com       -> .example.com
      DOMAIN-KEYWORD,google           -> *google*
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


def modify_readme_clash_section(readme_path, folder_name, classical_filename):
    """精确定位并替换 README.md 中的 Clash 模块"""
    if not os.path.exists(readme_path):
        return

    with open(readme_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    in_clash_section = False
    clash_level = 0
    clash_processed = False

    cb = "```"
    replacement_text = (
        f"\nDomain 规则（必须同时使用）\n"
        f"{cb}text\n"
        f"{RAW_BASE_URL}/{folder_name}/{folder_name}_Domain.mrs\n"
        f"{cb}\n\n"
        f"IP 规则（必须同时使用）\n"
        f"{cb}text\n"
        f"{RAW_BASE_URL}/{folder_name}/{folder_name}_IP.mrs\n"
        f"{cb}\n\n"
        f"Classical 规则（单独使用）\n"
        f"{cb}text\n"
        f"{RAW_BASE_URL}/{folder_name}/{classical_filename}\n"
        f"{cb}\n\n"
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

    with open(readme_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def modify_root_readme_links(content):
    """
    替换 Clash 根 README 里的上游链接为自己的仓库链接。

    兼容：
      markdown 链接
      纯文本链接
    """
    upstream_tree_url = "https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash"
    upstream_blob_url = "https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash"

    content = content.replace(
        f"[{upstream_tree_url}]({upstream_tree_url})",
        f"[{MY_REPO_URL}]({MY_REPO_URL})"
    )

    content = content.replace(upstream_tree_url, MY_REPO_URL)
    content = content.replace(upstream_blob_url, MY_REPO_URL)

    return content


def select_best_yaml(folder_path, folder_name):
    """
    优先选择最全的 Classical YAML。
    如果没有，则选择普通 YAML。
    """
    classical_yaml = os.path.join(folder_path, f"{folder_name}_Classical.yaml")
    normal_yaml = os.path.join(folder_path, f"{folder_name}.yaml")

    if os.path.exists(classical_yaml):
        return classical_yaml

    if os.path.exists(normal_yaml):
        return normal_yaml

    return None


def main():
    print("开始执行 Clash 规则拆分与 MRS 编译任务...")

    if os.path.exists(DEST_CLASH_DIR):
        shutil.rmtree(DEST_CLASH_DIR)

    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

    os.makedirs(TEMP_DIR, exist_ok=True)

    if not os.path.exists(SOURCE_CLASH_DIR):
        print(f"严重错误: 找不到上游源码目录 {SOURCE_CLASH_DIR}")
        return

    # 复制并修改 Clash 根目录 README.md
    src_root_readme = os.path.join(SOURCE_CLASH_DIR, "README.md")
    dest_root_readme = os.path.join(DEST_CLASH_DIR, "README.md")

    if os.path.exists(src_root_readme):
        with open(src_root_readme, "r", encoding="utf-8") as f:
            root_content = f.read()

        root_content = modify_root_readme_links(root_content)

        with open(dest_root_readme, "w", encoding="utf-8") as f:
            f.write(root_content)

    print("开始拆分并编译规则...")

    total_folders = 0
    compiled_domain = 0
    compiled_ip = 0
    skipped_no_yaml = 0

    for item in sorted(os.listdir(SOURCE_CLASH_DIR)):
        folder_path = os.path.join(SOURCE_CLASH_DIR, item)

        if not os.path.isdir(folder_path):
            continue

        target_yaml = select_best_yaml(folder_path, item)

        if not target_yaml:
            skipped_no_yaml += 1
            continue

        total_folders += 1
        print(f"\n正在处理目录: {item}")

        dest_folder = os.path.join(DEST_CLASH_DIR, item)
        os.makedirs(dest_folder, exist_ok=True)

        target_filename = os.path.basename(target_yaml)
        dest_yaml_path = os.path.join(dest_folder, target_filename)

        # 保留最全的 Classical YAML；如果没有则保留普通 YAML
        shutil.copy2(target_yaml, dest_yaml_path)

        domain_rules, ip_rules = split_yaml_payload(target_yaml)

        print(f"Domain 规则数量: {len(domain_rules)}")
        print(f"IP CIDR 规则数量: {len(ip_rules)}")

        domain_mrs_path = os.path.join(dest_folder, f"{item}_Domain.mrs")
        ip_mrs_path = os.path.join(dest_folder, f"{item}_IP.mrs")

        # Domain MRS
        if domain_rules:
            temp_domain_yaml = os.path.join(TEMP_DIR, f"{item}_temp_domain.yaml")
            write_mrs_source_yaml(temp_domain_yaml, domain_rules)

            if compile_to_mrs(temp_domain_yaml, domain_mrs_path, "domain"):
                compiled_domain += 1
        else:
            print(f"跳过 Domain.mrs：{item} 没有可转换的 Domain 规则")

        # IP MRS
        if ip_rules:
            temp_ip_yaml = os.path.join(TEMP_DIR, f"{item}_temp_ip.yaml")
            write_mrs_source_yaml(temp_ip_yaml, ip_rules)

            if compile_to_mrs(temp_ip_yaml, ip_mrs_path, "ipcidr"):
                compiled_ip += 1
        else:
            print(f"跳过 IP.mrs：{item} 没有可转换的 IP-CIDR/IP-CIDR6 规则")

        # 复制并修改子目录 README.md
        src_readme = os.path.join(folder_path, "README.md")
        dest_readme = os.path.join(dest_folder, "README.md")

        if os.path.exists(src_readme):
            shutil.copy2(src_readme, dest_readme)
            modify_readme_clash_section(dest_readme, item, target_filename)

    print("\n清理临时编译环境...")

    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)

    print("\n转换与编译全部完成！")
    print(f"处理目录数量: {total_folders}")
    print(f"成功编译 Domain.mrs 数量: {compiled_domain}")
    print(f"成功编译 IP.mrs 数量: {compiled_ip}")
    print(f"跳过无 YAML 目录数量: {skipped_no_yaml}")


if __name__ == "__main__":
    main()
