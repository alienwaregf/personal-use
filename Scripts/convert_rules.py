import os
import re
import shutil
import subprocess

# ================= 核心配置 =================
# 自动读取 Action 通过 git clone 拉取到的源文件夹
SOURCE_CLASH_DIR = os.path.join("source_repo", "rule", "Clash")
DEST_CLASH_DIR = os.path.join("rule", "Clash")

# 用于存放交给 Mihomo 内核编译的临时分离 yaml 文件
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
    # Action 已将 mihomo 安装到 /usr/local/bin/mihomo
    cmd = ["mihomo", "convert-ruleset", rule_type, "yaml", temp_yaml_path, out_mrs_path]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"编译 {out_mrs_path} 失败: {e}")

def modify_readme_clash_section(readme_path, folder_name, classical_filename):
    """
    重写后的精确定位函数：基于 Markdown 标题层级进行判断。
    只清空 Clash 模块内的所有子级内容（如 ### 文件区别等），
    遇到下一个同级或更高级别标题（如 ## 子规则/排除规则）时完美停止并保留后续内容。
    """
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
        # 精确寻找单独的 Clash 标题行（如 "## Clash"）
        header_match = re.match(r'^(#+)\s*Clash\s*$', line.strip(), re.IGNORECASE)
        if header_match and not clash_processed:
            in_clash_section = True
            clash_level = len(header_match.group(1)) # 记录 Clash 是几级标题 (比如 2)
            new_lines.append(line.rstrip() + "\n")   # 保留这个 "## Clash" 标题本身
            new_lines.append(replacement_text)       # 注入我们的 mrs 链接
            clash_processed = True
            continue
            
        if in_clash_section:
            # 在 Clash 模块内部，检查是否遇到了新的标题
            other_header_match = re.match(r'^(#+)\s+(.*)$', line.strip())
            if other_header_match:
                current_level = len(other_header_match.group(1))
                # 如果新标题的层级 <= Clash 的层级（比如也是 ## 或者更高的 #）
                # 意味着 Clash 模块结束，进入了如 "## 子规则/排除规则" 等下一个大模块
                if current_level <= clash_level:
                    in_clash_section = False
                    new_lines.append(line)
            # 如果没有触发跳出条件，说明当前行是 Clash 模块内的旧文本或子标题（如 ###），直接丢弃（不 append）
        else:
            # 不在 Clash 模块内，或者已经跳出了 Clash 模块，正常保留原文
            new_lines.append(line)
            
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

def main():
    print("开始执行规则拆分与原生 MRS 编译任务...")

    # 1. 初始化目标目录与临时编译目录
    if os.path.exists(DEST_CLASH_DIR):
        shutil.rmtree(DEST_CLASH_DIR)
    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    # 验证上游源码仓库是否存在
    if not os.path.exists(SOURCE_CLASH_DIR):
        print(f"严重错误: 找不到上游源码目录 {SOURCE_CLASH_DIR}。")
        print("请检查 Action 的 git clone 步骤是否成功生成了 source_repo 文件夹。")
        return

    # 2. 处理根目录 README.md (替换所有分类链接地址)
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
    
    # 3. 遍历并处理各子文件夹
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

        # 优先将最全的原生 yaml 保留进个人仓库
        shutil.copy2(target_yaml, dest_yaml_path)

        # 从原版 yaml 完全无损提取拆分 Domain 与 IP 规则组
        domain_rules, ip_rules = split_yaml_payload(target_yaml)

        # 生成临时的 YAML 文件以供内核识别编译
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

        # 调用全局环境中的 Mihomo 内核进行底层编译
        domain_mrs_path = os.path.join(dest_folder, f"{item}_Domain.mrs")
        ip_mrs_path = os.path.join(dest_folder, f"{item}_IP.mrs")
        
        compile_to_mrs(temp_domain_yaml, domain_mrs_path, "domain")
        compile_to_mrs(temp_ip_yaml, ip_mrs_path, "ipcidr")

        # 4. 替换子目录 README.md
        src_readme = os.path.join(folder_path, "README.md")
        dest_readme = os.path.join(dest_folder, "README.md")
        if os.path.exists(src_readme):
            shutil.copy2(src_readme, dest_readme)
            modify_readme_clash_section(dest_readme, item, target_filename)

    # 5. 清理当前脚本产生的临时编译文件 (Action 会负责清理源码目录)
    print("清理临时编译环境...")
    shutil.rmtree(TEMP_DIR)
    print("转换与编译全部完成！")

if __name__ == "__main__":
    main()
