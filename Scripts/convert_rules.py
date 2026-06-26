import os
import re
import shutil
import subprocess

# ================= 核心配置 =================
SOURCE_CLASH_DIR = os.path.join("source_repo", "rule", "Clash")
DEST_CLASH_DIR = os.path.join("rule", "Clash")
TEMP_DIR = "temp_compile" 

MY_REPO_URL = "https://github.com/alienwaregf/personal-use/tree/main/rule/Clash"
RAW_BASE_URL = "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash"

def split_yaml_payload(filepath):
    """提取原始 YAML，将规则按 Domain 和 IP 进行无损拆分，保持原样字符串"""
    domain_rules = []
    ip_rules = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            payload_started = False
            for line in f:
                stripped = line.strip()
                if stripped == 'payload:':
                    payload_started = True
                    continue
                if payload_started and stripped.startswith('-'):
                    # 获取规则类型标识（如 DOMAIN-SUFFIX, IP-CIDR 等）
                    rule_content = stripped[2:].strip('\'" ').upper()
                    if rule_content.startswith(('DOMAIN', 'GEOSITE')):
                        domain_rules.append(stripped)
                    elif rule_content.startswith(('IP-', 'GEOIP', 'SRC-IP')):
                        ip_rules.append(stripped)
    except Exception as e:
        print(f"读取 {filepath} 时出错: {e}")
        
    return domain_rules, ip_rules

def compile_to_mrs(temp_yaml_path, out_mrs_path, rule_type):
    """调用全局环境中的 Mihomo 内核进行编译"""
    cmd = ["mihomo", "convert-ruleset", rule_type, "yaml", temp_yaml_path, out_mrs_path]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"编译 {out_mrs_path} 失败: {e}")

def modify_readme_clash_section(readme_path, folder_name, classical_filename):
    """精确定位并替换 README.md 中的 Clash 模块"""
    if not os.path.exists(readme_path):
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
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
        header_match = re.match(r'^(#+)\s*Clash\s*$', line.strip(), re.IGNORECASE)
        if header_match and not clash_processed:
            in_clash_section = True
            clash_level = len(header_match.group(1))
            new_lines.append(line.rstrip() + "\n")
            new_lines.append(replacement_text)
            clash_processed = True
            continue
            
        if in_clash_section:
            other_header_match = re.match(r'^(#+)\s+(.*)$', line.strip())
            if other_header_match:
                current_level = len(other_header_match.group(1))
                if current_level <= clash_level:
                    in_clash_section = False
                    new_lines.append(line)
        else:
            new_lines.append(line)
            
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

def main():
    print("开始执行规则拆分与原生 MRS 编译任务...")

    if os.path.exists(DEST_CLASH_DIR):
        shutil.rmtree(DEST_CLASH_DIR)
    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    if not os.path.exists(SOURCE_CLASH_DIR):
        print(f"严重错误: 找不到上游源码目录 {SOURCE_CLASH_DIR}。")
        return

    src_root_readme = os.path.join(SOURCE_CLASH_DIR, "README.md")
    dest_root_readme = os.path.join(DEST_CLASH_DIR, "README.md")
    if os.path.exists(src_root_readme):
        with open(src_root_readme, 'r', encoding='utf-8') as f:
            root_content = f.read()
        
        root_content = root_content.replace(
            "[https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash)",
            MY_REPO_URL
        )
        with open(dest_root_readme, 'w', encoding='utf-8') as f:
            f.write(root_content)

    print("开始无损拆分并编译规则...")
    
    for item in os.listdir(SOURCE_CLASH_DIR):
        folder_path = os.path.join(SOURCE_CLASH_DIR, item)
        if not os.path.isdir(folder_path):
            continue

        classical_yaml = os.path.join(folder_path, f"{item}_Classical.yaml")
        normal_yaml = os.path.join(folder_path, f"{item}.yaml")
        
        target_yaml = None
        if os.path.exists(classical_yaml):
            target_yaml = classical_yaml
        elif os.path.exists(normal_yaml):
            target_yaml = normal_yaml

        if not target_yaml:
            continue

        print(f"正在处理与编译目录: {item}")
        dest_folder = os.path.join(DEST_CLASH_DIR, item)
        os.makedirs(dest_folder, exist_ok=True)

        target_filename = os.path.basename(target_yaml)
        dest_yaml_path = os.path.join(dest_folder, target_filename)

        shutil.copy2(target_yaml, dest_yaml_path)

        domain_rules, ip_rules = split_yaml_payload(target_yaml)

        temp_domain_yaml = os.path.join(TEMP_DIR, f"{item}_temp_domain.yaml")
        temp_ip_yaml = os.path.join(TEMP_DIR, f"{item}_temp_ip.yaml")
        
        with open(temp_domain_yaml, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for r in domain_rules:
                f.write(f"  {r}\n")
                
        with open(temp_ip_yaml, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for r in ip_rules:
                f.write(f"  {r}\n")

        # 【核心修正】：统一使用 "classical" 参数，让内核正确识别并压制带前缀的规则格式！
        domain_mrs_path = os.path.join(dest_folder, f"{item}_Domain.mrs")
        ip_mrs_path = os.path.join(dest_folder, f"{item}_IP.mrs")
        
        compile_to_mrs(temp_domain_yaml, domain_mrs_path, "classical")
        compile_to_mrs(temp_ip_yaml, ip_mrs_path, "classical")

        src_readme = os.path.join(folder_path, "README.md")
        dest_readme = os.path.join(dest_folder, "README.md")
        if os.path.exists(src_readme):
            shutil.copy2(src_readme, dest_readme)
            modify_readme_clash_section(dest_readme, item, target_filename)

    print("清理临时编译环境...")
    shutil.rmtree(TEMP_DIR)
    print("转换与编译全部完成！")

if __name__ == "__main__":
    main()
