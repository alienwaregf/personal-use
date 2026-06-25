import os
import re
import shutil
import subprocess
import yaml

# ================= 配置区域 =================
GITHUB_USER = "alienwaregf"
GITHUB_REPO = "personal-use"
SOURCE_ROOT = "source_repo/rule/Clash"
DEST_ROOT = "rule/Clash"
BASE_RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/rule/Clash"

# 在这里填入你手动创建、绝对不能被自动清理的文件夹名称
PROTECTED_DIRS = ["AdobeApp", "ChinaDirect", "IP", "Perplexity"] 
# ===========================================

def process_rules():
    if not os.path.exists(DEST_ROOT):
        os.makedirs(DEST_ROOT)

    # 1. 扫描上游目录，获取合法分类
    valid_dirs = set()
    for root, dirs, files in os.walk(SOURCE_ROOT):
        rel_path = os.path.relpath(root, SOURCE_ROOT)
        if rel_path != ".":
            valid_dirs.add(rel_path.split(os.sep)[0])

    # 2. 同步与编译处理
    for root, dirs, files in os.walk(SOURCE_ROOT):
        rel_path = os.path.relpath(root, SOURCE_ROOT)
        target_dir = DEST_ROOT if rel_path == "." else os.path.join(DEST_ROOT, rel_path)
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        category_name = os.path.basename(root)

        if rel_path == ".":
            if "README.md" in files:
                rewrite_readme(os.path.join(root, "README.md"), os.path.join(target_dir, "README.md"), rel_path, category_name, {})
            continue

        # 优选保留 _Classical.yaml 或标准 .yaml
        classical_yaml = f"{category_name}_Classical.yaml"
        standard_yaml = f"{category_name}.yaml"
        if classical_yaml in files:
            shutil.copy2(os.path.join(root, classical_yaml), os.path.join(target_dir, classical_yaml))
        elif standard_yaml in files:
            shutil.copy2(os.path.join(root, standard_yaml), os.path.join(target_dir, standard_yaml))

        # 编译 MRS
        domains, ips = extract_rules(root, files)
        generated_mrs = {}
        if domains:
            if compile_ruleset(domains, os.path.join(target_dir, f"{category_name}_Domain.mrs"), 'domain'):
                generated_mrs['domain'] = f"{category_name}_Domain.mrs"
        if ips:
            if compile_ruleset(ips, os.path.join(target_dir, f"{category_name}_IP.mrs"), 'ipcidr'):
                generated_mrs['ip'] = f"{category_name}_IP.mrs"

        if "README.md" in files:
            rewrite_readme(os.path.join(root, "README.md"), os.path.join(target_dir, "README.md"), rel_path, category_name, generated_mrs)

    # 3. 自动清理机制：删除上游不存在且未被保护的文件夹
    for folder in os.listdir(DEST_ROOT):
        folder_path = os.path.join(DEST_ROOT, folder)
        if os.path.isdir(folder_path) and folder not in PROTECTED_DIRS and folder not in valid_dirs:
            shutil.rmtree(folder_path)
            print(f"检测到上游废弃，已清理: {folder}")

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
                    if parts[0].upper() in ['DOMAIN-SUFFIX', 'DOMAIN']: domains.append(parts[1])
                    elif parts[0].upper() in ['IP-CIDR', 'IP-CIDR6']: ips.append(parts[1])
    return list(set(domains)), list(set(ips))

def compile_ruleset(data, output_path, behavior):
    yaml_path = output_path.replace('.mrs', '.yaml')
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump({"payload": data}, f, allow_unicode=True, default_flow_style=False)
    try:
        subprocess.run(['mihomo', 'convert-ruleset', behavior, 'yaml', yaml_path, output_path], check=True)
        return True
    except: return False

def rewrite_readme(src_path, dst_path, rel_path, category, generated_mrs):
    with open(src_path, 'r', encoding='utf-8') as f: content = f.read()
    if rel_path == ".":
        content = content.replace("blackmatrix7/ios_rule_script", f"{GITHUB_USER}/{GITHUB_REPO}")
        new_content = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', lambda m: f"[{m.group(1)}](https://github.com/{GITHUB_USER}/{GITHUB_REPO}/tree/main/rule/Clash/{m.group(2)})" if not m.group(2).startswith("http") else m.group(0), content)
        with open(dst_path, 'w', encoding='utf-8') as f: f.write(new_content)
    else:
        content = re.sub(r'#{2,3}\s*使用说明.*?(?=\n#{2,3}\s|\Z)', '', content, flags=re.DOTALL)
        content = re.sub(r'#{2,3}\s*配置建议.*?(?=\n#{2,3}\s|\Z)', '', content, flags=re.DOTALL)
        suffix = " (必须同时使用)" if ('domain' in generated_mrs and 'ip' in generated_mrs) else ""
        my_links = "### ⬇️ MRS 规则下载链接\n\n"
        if 'domain' in generated_mrs: my_links += f"- **Domain 规则{suffix}**: [{generated_mrs['domain']}]({BASE_RAW_URL}/{rel_path.replace(chr(92), '/')}/{generated_mrs['domain']})\n"
        if 'ip' in generated_mrs: my_links += f"- **IP 规则{suffix}**: [{generated_mrs['ip']}]({BASE_RAW_URL}/{rel_path.replace(chr(92), '/')}/{generated_mrs['ip']})\n"
        content = re.sub(r'### 规则链接.*?(?=\n## |\Z)', my_links, content, flags=re.DOTALL)
        with open(dst_path, 'w', encoding='utf-8') as f: f.write(content)

if __name__ == "__main__": process_rules()
