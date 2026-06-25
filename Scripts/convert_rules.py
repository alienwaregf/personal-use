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

        # 1. 提取当前目录生成的规则数据
        category_name = os.path.basename(root)
        domains, ips = extract_rules(root, files)

        # 2. 编译 MRS 文件并记录生成的文件名
        generated_mrs = {}
        if domains:
            domain_mrs = f"{category_name}_Domain.mrs"
            if compile_ruleset(domains, os.path.join(target_dir, domain_mrs), 'domain'):
                generated_mrs['domain'] = domain_mrs
        if ips:
            ip_mrs = f"{category_name}_IP.mrs"
            if compile_ruleset(ips, os.path.join(target_dir, ip_mrs), 'ipcidr'):
                generated_mrs['ip'] = ip_mrs

        # 3. 智能处理 README.md：重写链接区块
        if "README.md" in files:
            source_readme_path = os.path.join(root, "README.md")
            target_readme_path = os.path.join(target_dir, "README.md")
            rewrite_readme(source_readme_path, target_readme_path, rel_path, category_name, generated_mrs)

def extract_rules(root, files):
    domains, ips = [], []
    for file in files:
        if file.endswith(('.yaml', '.list')):
            with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    line = line.replace('- ', '').replace("'", "")
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
        return True
    except:
        return False
    finally:
        if os.path.exists(temp_yaml): os.remove(temp_yaml)

def rewrite_readme(src_path, dst_path, rel_path, category, generated_mrs):
    with open(src_path, 'r', encoding='utf-8') as f:
        content = f.read()

    url_rel_path = rel_path.replace("\\", "/")
    
    # 构建我们自己的专属干净链接区块
    my_links = "### ⬇️ MRS 规则下载链接\n\n"
    if 'domain' in generated_mrs:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        my_links += f"- **Domain 规则 (推荐)**: [{generated_mrs['domain']}]({mrs_url})\n"
    if 'ip' in generated_mrs:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        my_links += f"- **IP 规则**: [{generated_mrs['ip']}]({mrs_url})\n"
    my_links += "\n"

    # 核心修改：使用正则定位原版 "### 规则链接" 及其后面的所有冗余链接，直到遇到下一个 "## " 二级标题
    # (?s) 即 re.DOTALL，让正则能跨行匹配
    pattern = r'### 规则链接.*?(?=\n## |\Z)'
    
    if re.search(pattern, content, re.DOTALL):
        # 找到了该区块，将原版的 6 个链接直接切除，替换成我们刚刚生成的 1-2 个清爽链接
        new_content = re.sub(pattern, my_links, content, flags=re.DOTALL)
    else:
        # 如果特殊情况没找到，就把我们的链接塞到文档末尾
        new_content = content + "\n\n" + my_links
        
    header = f"> [!TIP]\n> 本目录下的规则已由上游 classical 格式自动转换为 Mihomo Binary MRS 格式。\n\n"
    
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write(header + new_content)
    print(f"已重写 README: {rel_path}")

if __name__ == "__main__":
    process_rules()
