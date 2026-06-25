import os
import glob
import subprocess
import yaml

SOURCE_DIR = "source_repo/rule/Clash"
DEST_DIR = "rule/Clash"

def process_rules():
    if not os.path.exists(DEST_DIR):
        os.makedirs(DEST_DIR)

    for root, dirs, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.endswith(('.yaml', '.list')):
                file_path = os.path.join(root, file)
                category_name = os.path.basename(root) # 例如 Google, Apple
                
                domains = []
                ips = []
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'): continue
                        
                        # 兼容 yaml payload 和 list
                        line = line.replace('- ', '').replace("'", "")
                        parts = line.split(',')
                        
                        if len(parts) < 2:
                            continue
                            
                        rule_type = parts[0].upper()
                        value = parts[1] # 直接提取核心域名/IP，顺便剥离掉可能附带的策略组名
                        
                        # 转化为 mrs 规则集支持的纯净格式
                        if rule_type == 'DOMAIN-SUFFIX':
                            domains.append('+.' + value)
                        elif rule_type == 'DOMAIN':
                            domains.append(value)
                        elif rule_type in ('IP-CIDR', 'IP-CIDR6'):
                            ips.append(value)

                # 列表去重
                domains = list(set(domains))
                ips = list(set(ips))

                if domains:
                    domain_yaml = f"{DEST_DIR}/{category_name}_Domain.yaml"
                    domain_mrs = f"{DEST_DIR}/{category_name}_Domain.mrs"
                    write_yaml(domain_yaml, domains)
                    compile_mrs(domain_yaml, domain_mrs, 'domain')

                if ips:
                    ip_yaml = f"{DEST_DIR}/{category_name}_IP.yaml"
                    ip_mrs = f"{DEST_DIR}/{category_name}_IP.mrs"
                    write_yaml(ip_yaml, ips)
                    compile_mrs(ip_yaml, ip_mrs, 'ipcidr')

def write_yaml(filepath, rules):
    payload = {"payload": rules}
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(payload, f, allow_unicode=True, default_flow_style=False)

def compile_mrs(yaml_path, mrs_path, behavior):
    try:
        # 修改点：正确的 ruleset 转换指令，并动态指定 behavior
        subprocess.run(['mihomo', 'convert-ruleset', behavior, 'yaml', yaml_path, mrs_path], check=True)
        os.remove(yaml_path) # 编译成功后清理中间产物
    except subprocess.CalledProcessError as e:
        print(f"编译失败: {yaml_path} - {e}")

if __name__ == "__main__":
    process_rules()
