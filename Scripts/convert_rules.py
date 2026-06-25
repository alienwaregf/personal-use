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
    # 确保目标根目录存在
    if not os.path.exists(DEST_ROOT):
        os.makedirs(DEST_ROOT)

    # ==================== 本地自定义规则热引入引擎 ====================
    # 如果你在本地 rule/Clash 下建立了自定义文件夹（如 IP）并放置了 yaml/list，将其注入临时工作区统一处理
    if os.path.exists(DEST_ROOT):
        for local_root, local_dirs, local_files in os.walk(DEST_ROOT):
            local_rel_path = os.path.relpath(local_root, DEST_ROOT)
            if local_rel_path == ".":
                continue
            for local_file in local_files:
                if local_file.endswith(('.yaml', '.list')):
                    src_f = os.path.join(local_root, local_file)
                    tgt_d = os.path.join(SOURCE_ROOT, local_rel_path)
                    os.makedirs(tgt_d, exist_ok=True)
                    shutil.copy2(src_f, os.path.join(tgt_d, local_file))

    # ==================== 核心循环：递归遍历所有规则目录 ====================
    for root, dirs, files in os.walk(SOURCE_ROOT):
        rel_path = os.path.relpath(root, SOURCE_ROOT)
        target_dir = DEST_ROOT if rel_path == "." else os.path.join(DEST_ROOT, rel_path)
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        category_name = os.path.basename(root)

        # ==================== 分支一：处理 rule/Clash 根目录大导航 ====================
        if rel_path == ".":
            if "README.md" in files:
                source_readme_path = os.path.join(root, "README.md")
                target_readme_path = os.path.join(target_dir, "README.md")
                rewrite_readme(source_readme_path, target_readme_path, rel_path, category_name, {})
            continue

        # ==================== 分支二：处理所有子目录（上游 + 个人自定义） ====================
        # 1. 自动优选并复制保存最全的纯文本配置
        classical_yaml = f"{category_name}_Classical.yaml"
        standard_yaml = f"{category_name}.yaml"

        # 如果存在多个，优先选择 _Classical.yaml
        if classical_yaml in files:
            src_yaml = os.path.join(root, classical_yaml)
            dst_yaml = os.path.join(target_dir, classical_yaml)
            shutil.copy2(src_yaml, dst_yaml)
            print(f"已优选保存纯文本规则: {rel_path}/{classical_yaml}")
        else:
            # 兼容处理用户自己命名的 yaml 文件，如 IP.yaml
            matched_yaml = [f for f in files if f.endswith('.yaml') and not f.endswith('.temp.yaml')]
            if matched_yaml:
                chosen_yaml = standard_yaml if standard_yaml in matched_yaml else matched_yaml[0]
                src_yaml = os.path.join(root, chosen_yaml)
                dst_yaml = os.path.join(target_dir, chosen_yaml)
                shutil.copy2(src_yaml, dst_yaml)
                print(f"已保存自定义文本规则: {rel_path}/{chosen_yaml}")

        # 2. 提取当前目录规则数据用于编译二进制 MRS
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

        # 4. 智能处理 README.md（即使自定义目录原本没有 README，也会强制自动完美创建）
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
                    elif rule_type == 'DOMAIN-WILDCARD': domains.append(value)
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
    # ==================== 根目录大 README 重写逻辑 ====================
    if rel_path == ".":
        if not os.path.exists(src_path): return
        with open(src_path, 'r', encoding='utf-8') as f:
            content = f.read()
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

    # ==================== 子目录小 README 重写与创建逻辑 ====================
    if os.path.exists(src_path):
        with open(src_path, 'r', encoding='utf-8') as f:
            content = f.read()
    else:
        # 如果是你自己创建的文件夹，缺失原版说明文档，这里会自动为你初始化一个干净的基础格式
        content = f"# 🧸 {category}\n\n## 前言\n这是个人自定义集成的分流规则库。\n\n## Clash\n"

    # 1. 干净利落地切除无用的旧使用说明块
    content = re.sub(r'#{2,3}\s*使用说明.*?(?=\n#{2,3}\s|\Z)', '', content, flags=re.DOTALL)
    content = re.sub(r'#{2,3}\s*配置建议.*?(?=\n#{2,3}\s|\Z)', '', content, flags=re.DOTALL)

    # 2. 动态组装下载链接 (集成 GitHub 原生一键复制功能)
    url_rel_path = rel_path.replace("\\", "/")
    my_links = "### ⬇️ MRS 规则下载链接\n\n"
    has_domain = 'domain' in generated_mrs
    has_ip = 'ip' in generated_mrs
    suffix = " (必须同时使用)" if (has_domain and has_ip) else ""

    if has_domain:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['domain']}"
        my_links += f"- **Domain 规则{suffix}**: [{generated_mrs['domain']}]({mrs_url})\n"
        my_links += f"  ```text\n  {mrs_url}\n  ```\n"
    if has_ip:
        mrs_url = f"{BASE_RAW_URL}/{url_rel_path}/{generated_mrs['ip']}"
        my_links += f"- **IP 规则{suffix}**: [{generated_mrs['ip']}]({mrs_url})\n"
        my_links += f"  ```text\n  {mrs_url}\n  ```\n"
    my_links += "\n"

    # 3. 采用高级区块替换，强行将链接锁定在 ## Clash 标题的正下方
    clash_pattern = r'(##\s*Clash\s*\n).*?(?=\n##\s|\Z)'
    if re.search(clash_pattern, content, re.DOTALL):
        new_content = re.sub(clash_pattern, r'\1\n' + my_links, content, flags=re.DOTALL)
    else:
        new_content = content + "\n\n" + my_links
        
    new_content = re.sub(r'\n{3,}', '\n\n', new_content)
    header = f"> [!TIP]\n> 本目录下的规则已由系统自动转换为 Mihomo Binary MRS 格式并保留了文本配置。\n\n"
    
    with open(dst_path, 'w', encoding='utf-8') as f:
        f.write(header + new_content)
    print(f"已重写并对齐 README: {rel_path}")

if __name__ == "__main__":
    process_rules()
