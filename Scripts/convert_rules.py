import os
import re
import sys
import shutil
import subprocess
import ipaddress
from collections import Counter

try:
    import yaml
except ImportError:
    yaml = None


# ================= 核心配置 =================
SOURCE_CLASH_DIR = os.path.join("source_repo", "rule", "Clash")
DEST_CLASH_DIR = os.path.join("rule", "Clash")
TEMP_DIR = "temp_compile"

MY_REPO_URL = "https://github.com/alienwaregf/personal-use/tree/main/rule/Clash"
RAW_BASE_URL = "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash"


# ================= 基础工具函数 =================
def strip_yaml_quote(value):
    """去掉字符串首尾引号。"""
    value = str(value).strip()

    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1].strip()

    return value


def clean_inline_comment(value):
    """清理简单行内注释。"""
    value = str(value).strip()

    if " #" in value:
        value = value.split(" #", 1)[0].strip()

    return value


def parse_payload_rule(rule):
    """
    把 payload 中的单条规则解析成 parts。

    示例：
      DOMAIN-SUFFIX,google.com
      IP-CIDR,1.1.1.0/24,no-resolve
    """
    if rule is None:
        return None

    raw = clean_inline_comment(strip_yaml_quote(rule))

    if not raw or raw.startswith("#"):
        return None

    parts = [strip_yaml_quote(p.strip()) for p in raw.split(",")]
    parts = [p for p in parts if p != ""]

    if not parts:
        return None

    parts[0] = parts[0].upper()
    return parts


def is_valid_domain_like(value):
    """
    粗略过滤明显不适合 domain behavior 的内容。

    允许：
      example.com
      +.example.com
      *.example.com
      xbox.*.microsoft.com
    """
    if not value:
        return False

    value = str(value).strip()

    bad_prefixes = (
        "http://",
        "https://",
        "regexp:",
        "geosite:",
        "geoip:",
    )

    if value.lower().startswith(bad_prefixes):
        return False

    if "/" in value:
        return False

    if "," in value:
        return False

    return True


def normalize_domain_rule(parts, skipped_counter=None):
    """
    把 Clash classical 域名规则转换成 Mihomo domain behavior 可用格式。

    能安全转换：
      DOMAIN,example.com              -> example.com
      DOMAIN-SUFFIX,example.com       -> +.example.com
      DOMAIN-WILDCARD,*.example.com   -> *.example.com

    不强行转换：
      DOMAIN-KEYWORD
      DOMAIN-REGEX
      GEOSITE
    """
    rule_type = parts[0].upper()

    if len(parts) < 2:
        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:缺少内容"] += 1
        return None

    value = strip_yaml_quote(parts[1])

    if not value:
        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:空内容"] += 1
        return None

    if rule_type == "DOMAIN":
        if is_valid_domain_like(value):
            return value

        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:非法域名"] += 1

        return None

    if rule_type == "DOMAIN-SUFFIX":
        value = value.lstrip(".")

        if is_valid_domain_like(value):
            return f"+.{value}"

        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:非法域名"] += 1

        return None

    if rule_type == "DOMAIN-WILDCARD":
        if is_valid_domain_like(value):
            return value

        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:非法通配"] += 1

        return None

    if rule_type in ("DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE"):
        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:不适合domain mrs"] += 1

        return None

    return None


def normalize_ipcidr_rule(parts, skipped_counter=None):
    """
    把 Clash classical IP 规则转换成 Mihomo ipcidr behavior 可用格式。

    只允许：
      IP-CIDR,1.1.1.0/24,no-resolve
      IP-CIDR6,2400:3200::/32,no-resolve

    转换后：
      1.1.1.0/24
      2400:3200::/32

    不放入 IP.mrs：
      GEOIP
      IP-ASN
      IP-SUFFIX
      SRC-IP-CIDR
      SRC-GEOIP
      SRC-IP-ASN
    """
    rule_type = parts[0].upper()

    if rule_type not in ("IP-CIDR", "IP-CIDR6"):
        if rule_type in (
            "GEOIP",
            "IP-ASN",
            "IP-SUFFIX",
            "SRC-IP-CIDR",
            "SRC-IP-SUFFIX",
            "SRC-GEOIP",
            "SRC-IP-ASN",
        ):
            if skipped_counter is not None:
                skipped_counter[f"{rule_type}:不适合ipcidr mrs"] += 1

        return None

    if len(parts) < 2:
        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:缺少CIDR"] += 1

        return None

    cidr = strip_yaml_quote(parts[1])

    if not cidr:
        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:空CIDR"] += 1

        return None

    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        if skipped_counter is not None:
            skipped_counter[f"{rule_type}:非法CIDR"] += 1

        print(f"跳过非法 CIDR: {','.join(parts)}")
        return None

    return cidr


def load_payload_rules(filepath):
    """
    读取 YAML 文件中的 payload 数组。

    优先使用 PyYAML。
    如果 PyYAML 失败，则用简易手动解析兜底。
    """
    if yaml is not None:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if isinstance(data, dict):
                payload = data.get("payload", [])

                if isinstance(payload, list):
                    return [str(x) for x in payload if x is not None]

        except Exception as e:
            print(f"PyYAML 读取失败，切换到手动解析: {filepath} -> {e}")

    rules = []

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

                if not stripped:
                    continue

                # 到达新的顶级字段时停止
                if not line.startswith((" ", "\t", "-")) and ":" in stripped:
                    break

                if stripped.startswith("-"):
                    raw = stripped[1:].strip()
                    raw = clean_inline_comment(strip_yaml_quote(raw))

                    if raw:
                        rules.append(raw)

    except Exception as e:
        print(f"读取 {filepath} 时出错: {e}")

    return rules


def split_yaml_payload(filepath):
    """
    提取原始 YAML payload，并转换成 MRS 支持的两种 behavior 内容：

    Domain.mrs:
      behavior: domain
      内容为普通域名 / 域名通配。

    IP.mrs:
      behavior: ipcidr
      内容为纯 CIDR。

    不能等价转换的规则不会硬塞进 MRS，会继续留在原始 Classical YAML 里。
    """
    domain_rules = []
    ip_rules = []

    domain_seen = set()
    ip_seen = set()
    skipped_counter = Counter()

    raw_rules = load_payload_rules(filepath)

    for raw_rule in raw_rules:
        parts = parse_payload_rule(raw_rule)

        if not parts:
            continue

        domain_value = normalize_domain_rule(parts, skipped_counter)

        if domain_value:
            if domain_value not in domain_seen:
                domain_seen.add(domain_value)
                domain_rules.append(domain_value)

            continue

        ip_value = normalize_ipcidr_rule(parts, skipped_counter)

        if ip_value:
            if ip_value not in ip_seen:
                ip_seen.add(ip_value)
                ip_rules.append(ip_value)

            continue

        rule_type = parts[0].upper()

        if rule_type not in (
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-WILDCARD",
            "DOMAIN-KEYWORD",
            "DOMAIN-REGEX",
            "GEOSITE",
            "IP-CIDR",
            "IP-CIDR6",
            "GEOIP",
            "IP-ASN",
            "IP-SUFFIX",
            "SRC-IP-CIDR",
            "SRC-IP-SUFFIX",
            "SRC-GEOIP",
            "SRC-IP-ASN",
        ):
            skipped_counter[f"{rule_type}:非域名/IP规则"] += 1

    return domain_rules, ip_rules, skipped_counter


def write_mrs_source_yaml(path, rules):
    """写入给 mihomo convert-ruleset 使用的临时 YAML。"""
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
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.stdout.strip():
            print(result.stdout.strip())

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


# ================= README 处理 =================
def build_child_readme_replacement(folder_name, classical_filename, has_domain_mrs=True, has_ip_mrs=True):
    """生成子目录 README.md 中 Clash 模块替换内容。"""
    cb = "```"
    parts = ["\n"]

    if has_domain_mrs:
        parts.append(
            f"Domain 规则（必须同时使用）\n"
            f"{cb}text\n"
            f"{RAW_BASE_URL}/{folder_name}/{folder_name}_Domain.mrs\n"
            f"{cb}\n\n"
        )
    else:
        parts.append("Domain 规则：当前目录没有可转换的 Domain MRS 规则。\n\n")

    if has_ip_mrs:
        parts.append(
            f"IP 规则（必须同时使用）\n"
            f"{cb}text\n"
            f"{RAW_BASE_URL}/{folder_name}/{folder_name}_IP.mrs\n"
            f"{cb}\n\n"
        )
    else:
        parts.append("IP 规则：当前目录没有可转换的 IP CIDR MRS 规则。\n\n")

    parts.append(
        f"Classical 规则（单独使用）\n"
        f"{cb}text\n"
        f"{RAW_BASE_URL}/{folder_name}/{classical_filename}\n"
        f"{cb}\n\n"
    )

    return "".join(parts)


def modify_readme_clash_section(
    readme_path,
    folder_name,
    classical_filename,
    has_domain_mrs=True,
    has_ip_mrs=True,
):
    """
    精确定位并替换 README.md 中的 Clash 模块。

    找到标题为 Clash 的章节；
    删除该章节内原来的使用说明、文件区别、配置建议等；
    替换成 Domain / IP / Classical 三段链接；
    保留 Clash 章节之后的其它内容。
    """
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
        stripped = line.strip()
        header_match = re.match(r"^(#+)\s*Clash\s*$", stripped, re.IGNORECASE)

        if header_match and not clash_processed:
            in_clash_section = True
            clash_level = len(header_match.group(1))
            new_lines.append(line.rstrip() + "\n")
            new_lines.append(replacement_text)
            clash_processed = True
            continue

        if in_clash_section:
            other_header_match = re.match(r"^(#+)\s+(.+)$", stripped)

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
      1. 上游 tree 链接
      2. 上游 blob 链接
      3. 上游 raw 链接
      4. README 里的相对目录链接，例如 ./Advertising
    """
    upstream_tree_url = "https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash"
    upstream_blob_url = "https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash"
    upstream_raw_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash"

    content = content.replace(upstream_tree_url, MY_REPO_URL)
    content = content.replace(upstream_blob_url, MY_REPO_URL)
    content = content.replace(upstream_raw_url, RAW_BASE_URL)

    def replace_markdown_link(match):
        label = match.group("label")
        url = match.group("url").strip()

        # 不处理锚点、http 链接、mailto 等
        if (
            not url
            or url.startswith("#")
            or url.startswith("http://")
            or url.startswith("https://")
            or url.startswith("mailto:")
        ):
            return match.group(0)

        normalized = url

        if normalized.startswith("./"):
            normalized = normalized[2:]

        normalized = normalized.strip("/")

        # 跳过父目录、当前目录、文件链接、多级路径
        if (
            not normalized
            or normalized.startswith("../")
            or normalized == "."
            or "/" in normalized
            or normalized.endswith(".md")
            or normalized.endswith(".yaml")
            or normalized.endswith(".yml")
            or normalized.endswith(".list")
            or normalized.endswith(".txt")
            or normalized.endswith(".mrs")
        ):
            return match.group(0)

        return f"[{label}]({MY_REPO_URL}/{normalized})"

    pattern = r"$begin:math:display$\(\?P\<label\>\[\^$end:math:display$]+)\]$begin:math:text$\(\?P\<url\>\[\^\)\]\+\)$end:math:text$"
    content = re.sub(pattern, replace_markdown_link, content)

    return content


# ================= 文件选择与主流程 =================
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


def print_skipped_summary(folder_name, skipped_counter):
    """打印当前目录不可转换规则摘要，避免日志过长。"""
    if not skipped_counter:
        return

    useful_items = [
        (k, v)
        for k, v in skipped_counter.items()
        if "不适合" in k or "非法" in k or "缺少" in k
    ]

    if not useful_items:
        return

    print(f"{folder_name} 不写入 MRS 的规则摘要:")

    for key, count in sorted(useful_items):
        print(f"  - {key}: {count}")


def clean_temp_dir():
    """清理脚本临时编译目录。"""
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)


def main():
    print("开始执行 Clash 规则拆分与 MRS 编译任务...")

    compile_failures = 0

    if os.path.exists(DEST_CLASH_DIR):
        shutil.rmtree(DEST_CLASH_DIR)

    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    clean_temp_dir()
    os.makedirs(TEMP_DIR, exist_ok=True)

    if not os.path.exists(SOURCE_CLASH_DIR):
        print(f"严重错误: 找不到上游源码目录 {SOURCE_CLASH_DIR}")
        sys.exit(1)

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
    total_skipped_counter = Counter()

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

        domain_rules, ip_rules, skipped_counter = split_yaml_payload(target_yaml)
        total_skipped_counter.update(skipped_counter)

        print(f"Domain MRS 规则数量: {len(domain_rules)}")
        print(f"IP CIDR MRS 规则数量: {len(ip_rules)}")
        print_skipped_summary(item, skipped_counter)

        domain_mrs_path = os.path.join(dest_folder, f"{item}_Domain.mrs")
        ip_mrs_path = os.path.join(dest_folder, f"{item}_IP.mrs")

        has_domain_mrs = False
        has_ip_mrs = False

        # Domain MRS
        if domain_rules:
            temp_domain_yaml = os.path.join(TEMP_DIR, f"{item}_temp_domain.yaml")
            write_mrs_source_yaml(temp_domain_yaml, domain_rules)

            if compile_to_mrs(temp_domain_yaml, domain_mrs_path, "domain"):
                compiled_domain += 1
                has_domain_mrs = True
            else:
                compile_failures += 1
        else:
            print(f"跳过 Domain.mrs：{item} 没有可转换的 Domain 规则")

        # IP MRS
        if ip_rules:
            temp_ip_yaml = os.path.join(TEMP_DIR, f"{item}_temp_ip.yaml")
            write_mrs_source_yaml(temp_ip_yaml, ip_rules)

            if compile_to_mrs(temp_ip_yaml, ip_mrs_path, "ipcidr"):
                compiled_ip += 1
                has_ip_mrs = True
            else:
                compile_failures += 1
        else:
            print(f"跳过 IP.mrs：{item} 没有可转换的 IP-CIDR/IP-CIDR6 规则")

        # 复制并修改子目录 README.md
        src_readme = os.path.join(folder_path, "README.md")
        dest_readme = os.path.join(dest_folder, "README.md")

        if os.path.exists(src_readme):
            shutil.copy2(src_readme, dest_readme)
            modify_readme_clash_section(
                dest_readme,
                item,
                target_filename,
                has_domain_mrs=has_domain_mrs,
                has_ip_mrs=has_ip_mrs,
            )

    print("\n清理临时编译环境...")
    clean_temp_dir()

    print("\n转换与编译完成。")
    print(f"处理目录数量: {total_folders}")
    print(f"成功编译 Domain.mrs 数量: {compiled_domain}")
    print(f"成功编译 IP.mrs 数量: {compiled_ip}")
    print(f"跳过无 YAML 目录数量: {skipped_no_yaml}")

    if total_skipped_counter:
        print("\n全部目录不可转换规则汇总:")

        for key, count in sorted(total_skipped_counter.items()):
            print(f"  - {key}: {count}")

    if compile_failures > 0:
        print(f"\n严重错误: 有 {compile_failures} 个 MRS 文件编译失败。")
        sys.exit(1)

    print("\n全部任务成功结束。")


if __name__ == "__main__":
    main()
