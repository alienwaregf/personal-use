import os
import shutil
import yaml
import subprocess
import re
import glob

# ================= 路径与基础配置 =================
SOURCE_REPO = 'source_repo'
SOURCE_CLASH_DIR = os.path.join(SOURCE_REPO, 'rule', 'Clash')
DEST_CLASH_DIR = os.path.join('rule', 'Clash')

# Github Raw 与 Tree 链接母地址
MY_REPO_URL_BASE = 'https://github.com/alienwaregf/personal-use/tree/main/rule/Clash'
RAW_URL_BASE = 'https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash'

def replace_clash_section(readme_content, category, domain_mrs_name, ip_mrs_name, yaml_name):
    """
    定位 README.md 中的 ## Clash 模块并进行替换。
    严格保留原有的 Surge/Quantumult X 等其他模块不动。
    """
    # 匹配 "## Clash" 到下一个 "## " 之前的所有内容（或者是文件结尾）
    pattern = re.compile(r'(##\s*Clash\s*\n.*?)(?=\n##\s+|\Z)', re.DOTALL | re.IGNORECASE)
    
    replacement = f"""## Clash

Domain 规则（必须同时使用）{domain_mrs_name}
{RAW_URL_BASE}/{category}/{domain_mrs_name}

IP 规则（必须同时使用）{ip_mrs_name}
{RAW_URL_BASE}/{category}/{ip_mrs_name}

Classical 规则（单独使用）{yaml_name}
{RAW_URL_BASE}/{category}/{yaml_name}"""

    if pattern.search(readme_content):
        return pattern.sub(replacement, readme_content)
    else:
        # 兜底：如果原 README 中没有 Clash 章节，则追加到尾部
        return readme_content.rstrip() + "\n\n" + replacement

def convert_rule_file(yaml_path, category, dest_folder):
    """
    解析原目标 YAML，分离出 Domain 和 IP 规则。
    生成适配 Mihomo mrs 编译的临时文件并触发转化，最后清理临时文件。
    """
    with open(yaml_path, 'r', encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            print(f"解析 YAML 失败，已跳过: {yaml_path} | 报错: {e}")
            return
            
    if not data or 'payload' not in data:
        return
        
    payload = data.get('payload', [])
    
    domain_payload = []
    ip_payload = []
    
    for line in payload:
        if not isinstance(line, str):
            continue
            
        parts = line.split(',')
        if len(parts) < 2:
            continue
            
        rule_type = parts[0].strip()
        # 获取规则内容，并通过截取 '#' 过滤掉行内注释，通过限制索引抛弃 'no-resolve' 等后缀
        rule_value = parts[1].split('#')[0].strip()
        
        # 拆分并转换为 Mihomo (Meta) 内核兼容的 Behavior 写法
        if rule_type == 'DOMAIN':
            domain_payload.append(rule_value)
        elif rule_type == 'DOMAIN-SUFFIX':
            # Clash 的 Suffix 在 Mihomo 的 domain behavior 中需要加上 +.
            domain_payload.append(f"+.{rule_value}")
        elif rule_type == 'DOMAIN-WILDCARD':
            domain_payload.append(rule_value)
        elif rule_type in ['IP-CIDR', 'IP-CIDR6']:
            ip_payload.append(rule_value)
        # DOMAIN-KEYWORD 不受 mihomo 原生 domain 基数树支持，为客观保证准确性予以抛弃
        # PROCESS-NAME, USER-AGENT 等由于不属于 Domain 或 IP，也同时丢弃
            
    domain_mrs_name = f"{category}_Domain.mrs"
    ip_mrs_name = f"{category}_IP.mrs"
    
    domain_mrs_path = os.path.join(dest_folder, domain_mrs_name)
    ip_mrs_path = os.path.join(dest_folder, ip_mrs_name)
    
    tmp_domain_yaml = os.path.join(dest_folder, "tmp_domain.yaml")
    tmp_ip_yaml = os.path.join(dest_folder, "tmp_ip.yaml")
    
    # 编译 Domain 规则
    if domain_payload:
        with open(tmp_domain_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': domain_payload}, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        subprocess.run(['mihomo', 'convert-ruleset', 'domain', 'yaml', tmp_domain_yaml, domain_mrs_path])
        if os.path.exists(tmp_domain_yaml):
            os.remove(tmp_domain_yaml)
            
    # 编译 IP 规则
    if ip_payload:
        with open(tmp_ip_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': ip_payload}, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        subprocess.run(['mihomo', 'convert-ruleset', 'ipcidr', 'yaml', tmp_ip_yaml, ip_mrs_path])
        if os.path.exists(tmp_ip_yaml):
            os.remove(tmp_ip_yaml)

def main():
    if not os.path.exists(DEST_CLASH_DIR):
        os.makedirs(DEST_CLASH_DIR)
        
    # --- 1. 处理母文件夹的 README.md ---
    src_root_readme = os.path.join(SOURCE_CLASH_DIR, 'README.md')
    dest_root_readme = os.path.join(DEST_CLASH_DIR, 'README.md')
    
    if os.path.exists(src_root_readme):
        with open(src_root_readme, 'r', encoding='utf-8') as f:
            root_content = f.read()
            
        # 替换母 README 内置顶的仓库地址指向你的项目
        root_content = root_content.replace(
            'https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash', 
            MY_REPO_URL_BASE
        )
        
        with open(dest_root_readme, 'w', encoding='utf-8') as f:
            f.write(root_content)
            
    # --- 2. 遍历黑矩阵的每一个子分类 ---
    for category in os.listdir(SOURCE_CLASH_DIR):
        cat_path = os.path.join(SOURCE_CLASH_DIR, category)
        
        # 忽略非目录项（例如上级的 README.md 本身）
        if not os.path.isdir(cat_path):
            continue
            
        dest_cat_folder = os.path.join(DEST_CLASH_DIR, category)
        os.makedirs(dest_cat_folder, exist_ok=True)
        
        # 定位需要转换的 YAML 文件
        yaml_files = glob.glob(os.path.join(cat_path, '*.yaml'))
        if not yaml_files:
            continue
            
        target_yaml = None
        # 优先保留目标全量文件 **_Classical.yaml
        for yf in yaml_files:
            if yf.endswith('_Classical.yaml'):
                target_yaml = yf
                break
                
        # 兜底：若没有 Classical 则随便抓取一个合规的 .yaml
        if not target_yaml:
            target_yaml = yaml_files[0]
            
        yaml_name = os.path.basename(target_yaml)
        dest_yaml_path = os.path.join(dest_cat_folder, yaml_name)
        
        # 将挑选的最全文件移动到你的对应分类目录里（排除其余无效格式）
        shutil.copy(target_yaml, dest_yaml_path)
        
        # --- 3. 剥离并生成对应的 Domain / IP 二进制文件 ---
        convert_rule_file(dest_yaml_path, category, dest_cat_folder)
        
        domain_mrs_name = f"{category}_Domain.mrs"
        ip_mrs_name = f"{category}_IP.mrs"
        
        # --- 4. 修改子文件夹的 README.md ---
        src_readme = os.path.join(cat_path, 'README.md')
        dest_readme = os.path.join(dest_cat_folder, 'README.md')
        
        if os.path.exists(src_readme):
            with open(src_readme, 'r', encoding='utf-8') as f:
                readme_content = f.read()
                
            # 覆写对应 Clash 模块并生成三个一键 URL
            new_readme_content = replace_clash_section(
                readme_content, 
                category, 
                domain_mrs_name, 
                ip_mrs_name, 
                yaml_name
            )
            
            with open(dest_readme, 'w', encoding='utf-8') as f:
                f.write(new_readme_content)

if __name__ == '__main__':
    main()
