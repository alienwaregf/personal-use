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

        # ==================== 特殊处理：如果是 rule/Clash 根目录 ====================
        if rel_path == ".":
            if "README.md" in files:
                source_readme_path = os.path.join(root, "README.md")
                target_readme_path = os.path.join(target_dir, "README.md")
                rewrite_readme(source_readme_path, target_readme_path, rel_path, category_name, {})
            continue # 跳过根目录的规则提取

        # 1. 自动复制保存原版最全的文本配置
        # 逻辑：优先寻找 _Classical.yaml，如果找到就不再管普通的 .yaml
        classical_yaml = f"{category_name}_Classical.yaml"
        standard_yaml = f"{category_name}.yaml"

        if classical_yaml in files:
            src_yaml = os.path.join(root, classical_yaml)
            dst_yaml = os.path.join(target_dir, classical_yaml)
            shutil.copy2(src_yaml, dst_yaml)
            print(f"已优选保留最全文本规则: {rel_path}/{classical_yaml}")
        elif standard_yaml in files:
            src_yaml = os.path.join(root, standard_yaml)
            dst_yaml = os.path.join(target_dir, standard_yaml)
            shutil.copy2(src_yaml, dst_yaml)
            print(f"已保留基础文本规则: {rel_path}/{standard_yaml}")

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

        # 4. 智能处理每个子目录的小 README.md：重写链接区块与删减内容
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

    # ==================== 分支一：处理 rule/Clash 根目录的大对齐 README ====================
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
        header = f"> [!TIP]\n> 本目录下的各分类规则已自动转换为 Mihomo Binary MRS 格式与文本 YAML 格式。\n\n"
        with open(dst_path, 'w', encoding='utf-8') as f:
            f.write(header + new_content)
        return

    # ==================== 分支二：处理各个子目录（如 Apple, Google）的小 README ====================
    url_rel_path = rel_path.replace("\\", "/")
    
    # 1. 精准删除不需要的“使用说明”和“配置建议”区块
    content = re.sub(r'#{2,3}\s*使用说明.*?(?=\n#{2,3}\s|\Z)', '', content, flags=re.DOTALL)
    content = re.sub(r'#{2,3}\s*配置建议.*?(?=\n#{2,3}\s|\Z)', '', content, flags=re.DOTALL)

    # 2. 构建专属链接及判断逻辑
    my_links = "### ⬇️ MRS 规则下载链接\n\n"
    has_domain = 'domain' in generated_mrs
    has_ip = 'ip' in generated_mrs
    
    suffix = " (必须同时使用)" if (has_domain and has_ip) else ""

    if has_domain:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        my_links += f"- **Domain 规则{suffix}**: [{generated_mrs['domain']}]({mrs_url})\n"
    if has_ip:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        my_links += f"- **IP 规则{suffix}**: [{generated_mrs['ip']}]({mrs_url})\n"
    my_links += "\n"

    # 3. 替换原有的“规则链接”区块
    pattern = r'### 规则链接.*?(?=\n## |\Z)'
    if re.search(pattern, content, re.DOTALL):
        new_content = re.sub(pattern, my_links, content, flags=re.DOTALL)
    else:
        new_content = content + "\n\n" + my_links
        
    new_content = re.sub(r'\n{3,}', '\n\n', new_content)
    header = f"> [!TIP]\n> 本目录下的规则已由上游 classical 格式自动转换为 Mihomo Binary MRS 格式并保留了最全的源文本配置。\n\n"
    
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write(header + new_content)
    print(f"已重写子目录 README: {rel_path}")

if __name__ == "__main__":
    process_rules()
