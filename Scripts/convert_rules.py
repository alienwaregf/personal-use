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

def process_rules():
    if not os.path.exists(DEST_ROOT):
        os.makedirs(DEST_ROOT)

    for root, dirs, files in os.walk(SOURCE_ROOT):
        rel_path = os.path.relpath(root, SOURCE_ROOT)
        target_dir = DEST_ROOT if rel_path == "." else os.path.join(DEST_ROOT, rel_path)
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        category_name = os.path.basename(root)

        # ==================== 特殊处理：如果是根目录 ====================
        if rel_path == ".":
            if "README.md" in files:
                rewrite_root_readme(os.path.join(root, "README.md"), os.path.join(target_dir, "README.md"))
            continue

        # 1. 拷贝文本规则，按你要求确定 Classical 编译源（_Classical 优先）
        classical_yaml = f"{category_name}_Classical.yaml"
        standard_yaml = f"{category_name}.yaml"
        yaml_for_classical = None

        if classical_yaml in files:
            shutil.copy2(os.path.join(root, classical_yaml), os.path.join(target_dir, classical_yaml))
            yaml_for_classical = os.path.join(target_dir, classical_yaml)
        elif standard_yaml in files:
            shutil.copy2(os.path.join(root, standard_yaml), os.path.join(target_dir, standard_yaml))
            yaml_for_classical = os.path.join(target_dir, standard_yaml)

        # 2. 提取并编译 Domain 和 IP 拆分规则
        domains, ips = extract_rules(root, files)
        generated_mrs = {}

        if domains:
            domain_mrs = f"{category_name}_Domain.mrs"
            if compile_ruleset(domains, os.path.join(target_dir, domain_mrs), 'domain'):
                generated_mrs['domain'] = domain_mrs
                
        if ips:
            ip_mrs = f"{category_name}_IP.mrs"
            if compile_ruleset(ips, os.path.join(target_dir, ip_mrs), 'ipcidr'):
                generated_mrs['ip'] = ip_mrs

        # 3. 编译 Classical 规则 (取消严格报错阻断，只要文件生成了就加链接)
        if yaml_for_classical:
            classical_mrs = f"{category_name}_Classical.mrs"
            classical_mrs_path = os.path.join(target_dir, classical_mrs)
            try:
                subprocess.run(['mihomo', 'convert-ruleset', 'classical', 'yaml', yaml_for_classical, classical_mrs_path])
                # 只要文件确实产出了，就记录到链接里
                if os.path.exists(classical_mrs_path):
                    generated_mrs['classical'] = classical_mrs
            except Exception as e:
                print(f"Classical 编译存在警告: {e}")

        # 4. 重写各子目录的小 README (生成一键复制代码块，精准控制位置)
        if "README.md" in files:
            rewrite_sub_readme(os.path.join(root, "README.md"), os.path.join(target_dir, "README.md"), rel_path, generated_mrs)

def extract_rules(root, files):
    domains, ips = [], []
    for file in files:
        if file.endswith(('.yaml', '.list')):
            with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    line = line.replace('- ', '').replace("'", "").replace('"', '')
                    parts = line.split(',')
                    if len(parts) < 2: continue
                    rule_type, value = parts[0].upper(), parts[1]
                    
                    if rule_type == 'DOMAIN-SUFFIX': domains.append('+.' + value)
                    elif rule_type == 'DOMAIN': domains.append(value)
                    elif rule_type in ('IP-CIDR', 'IP-CIDR6'): ips.append(value)
    return list(set(domains)), list(set(ips))

def compile_ruleset(data, output_path, behavior):
    temp_yaml = output_path + ".temp.yaml"
    with open(temp_yaml, 'w', encoding='utf-8') as f:
        yaml.dump({"payload": data}, f)
    try:
        subprocess.run(['mihomo', 'convert-ruleset', behavior, 'yaml', temp_yaml, output_path], check=True)
        return os.path.exists(output_path)
    except:
        return False
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def rewrite_root_readme(src_path, dst_path):
    with open(src_path, 'r', encoding='utf-8') as f: content = f.read()
    content = content.replace("https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash", 
                              f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash")
    content = content.replace("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash", 
                              f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/rule/Clash")
    def root_link_replacer(match):
        text, url = match.group(1), match.group(2).strip()
        return f"[{text}](https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash/{url})" if not url.startswith("http") and not url.startswith("#") else match.group(0)
    new_content = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', root_link_replacer, content)
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write("> [!TIP]\n> 本目录规则已自动转换为 Mihomo Binary MRS 格式与文本 YAML 格式。\n\n" + new_content)

def rewrite_sub_readme(src_path, dst_path, rel_path, generated_mrs):
    with open(src_path, 'r', encoding='utf-8') as f: content = f.read()
    url_rel_path = rel_path.replace("\\", "/")
    
    # 核心逻辑：精准提取到“规则统计”结束的地方，丢弃后面的所有残留废料
    match = re.search(r'(.*?## 规则统计.*?(?=\n## |\Z))', content, flags=re.DOTALL)
    if match:
        clean_content = match.group(1).strip()
    else:
        # 兜底：如果原文档没有规则统计，则在第一个不需要的模块处截断
        clean_content = re.sub(r'\n## (使用说明|配置建议|Clash|Surge|Quantumult X|Loon|Shadowrocket|通用).*', '', content, flags=re.DOTALL).strip()

    # ==================== 构建一键复制代码块排版 ====================
    my_links = "## Clash\n\n"
    has_domain, has_ip, has_classical = 'domain' in generated_mrs, 'ip' in generated_mrs, 'classical' in generated_mrs
    suffix = " (必须同时使用)" if (has_domain and has_ip) else ""

    if has_domain:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        my_links += f"**Domain 规则{suffix}:**\n\n```text\n{mrs_url}\n```\n\n"
    if has_ip:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        my_links += f"**IP 规则{suffix}:**\n\n```text\n{mrs_url}\n```\n\n"
    if has_classical:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['classical']}"
        my_links += f"**Classical 规则 (单独使用):**\n\n```text\n{mrs_url}\n```\n\n"

    # 将干净的内容与新的链接区块无缝拼接
    header = "> [!TIP]\n> 本目录下的规则已由上游格式自动转换为 Mihomo Binary MRS 格式。\n\n"
    final_content = header + clean_content + "\n\n" + my_links.strip() + "\n"
    
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write(final_content)

if __name__ == "__main__":
    process_rules()
