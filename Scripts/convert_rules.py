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

        # 如果是根目录，跳过规则提取和复制，只处理大 README 导航表
        if rel_path == ".":
            if "README.md" in files:
                source_readme_path = os.path.join(root, "README.md")
                target_readme_path = os.path.join(target_dir, "README.md")
                rewrite_readme(source_readme_path, target_readme_path, rel_path, category_name, {})
            continue

        # 1. 自动复制保存原版最全的文本配置 (.yaml 或 _Classical.yaml)
        target_yaml_files = [f"{category_name}.yaml", f"{category_name}_Classical.yaml"]
        for y_file in target_yaml_files:
            if y_file in files:
                src_yaml = os.path.join(root, y_file)
                dst_yaml = os.path.join(target_dir, y_file)
                shutil.copy2(src_yaml, dst_yaml)
                print(f"已保留原版文本规则: {rel_path}/{y_file}")

        # 2. 提取当前目录生成的规则数据用于编译二进制 MRS
        domains, ips = extract_rules(root, files)

        # 3. 编译 MRS 文件并记录生成的文件名
        generated_mrs = {}
        if domains:
            domain_mrs = f"{category_name}_Domain.mrs"
            if compile_ruleset(domains, os.path.join(target_dir, domain_mrs), 'domain'):
                generated_mrs['domain'] = domain_mrs
        if ips:
            ip_mrs = f"{category_name}_IP.mrs"
            if compile_ruleset(ips, os.path.join(target_dir, ip_mrs), 'ipcidr'):
                generated_mrs['ip'] = ip_mrs

        # 4. 智能处理 README.md：重写链接区块
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

    # ==================== 分支一：处理 rule/Clash 根目录的大 README ====================
    if rel_path == ".":
        content = content.replace("https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash", 
                                  f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash")
        content = content.replace("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash", 
                                  f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/rule/Clash")
        
        def root_link_replacer(match):
            text = match.group(1)
            url = match.group(2).strip()
            if not url.startswith("http") and not url.startswith("#"):
                return f"[{text}](https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash/{url})"
            return match.group(0)
        
        new_content = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', root_link_replacer, content)
        header = f"> [!TIP]\n> 本目录下的各分类规则已自动转换为 Mihomo Binary MRS 格式。点击下方分类文件夹即可直达你自己的对应目录网页查看与下载。\n\n"
        with open(dst_path, 'w', encoding='utf-8') as f:
            f.write(header + new_content)
        print("已完美重写根目录大 README.md 的直达链接")
        return

    # ==================== 分支二：处理各个子目录的小 README ====================
    url_rel_path = rel_path.replace("\\", "/")
    my_links = "### ⬇️ MRS 规则下载链接\n\n"
    if 'domain' in generated_mrs:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        my_links += f"- **Domain 规则 (推荐)**: [{generated_mrs['domain']}]({mrs_url})\n"
    if 'ip' in generated_mrs:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        my_links += f"- **IP 规则**: [{generated_mrs['ip']}]({mrs_url})\n"
    my_links += "\n"

    pattern = r'### 规则链接.*?(?=\n## |\Z)'
    if re.search(pattern, content, re.DOTALL):
        new_content = re.sub(pattern, my_links, content, flags=re.DOTALL)
    else:
        new_content = content + "\n\n" + my_links
        
    header = f"> [!TIP]\n> 本目录下的规则已由上游 classical 格式自动转换为 Mihomo Binary MRS 格式。\n\n"
    
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write(header + new_content)
    print(f"已重写子目录 README: {rel_path}")

if __name__ == "__main__":
    process_rules()
