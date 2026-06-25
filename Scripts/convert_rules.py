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
                        
                        line = line.replace('- ', '').replace("'", "")
                        
                        if 'DOMAIN' in line:
                            domains.append(line)
                        elif 'IP-CIDR' in line or 'IP-ASN' in line:
                            ips.append(line)

                if domains:
                    domain_yaml = f"{DEST_DIR}/{category_name}_Domain.yaml"
                    domain_mrs = f"{DEST_DIR}/{category_name}_Domain.mrs"
                    write_yaml(domain_yaml, domains)
                    compile_mrs(domain_yaml, domain_mrs)

                if ips:
                    ip_yaml = f"{DEST_DIR}/{category_name}_IP.yaml"
                    ip_mrs = f"{DEST_DIR}/{category_name}_IP.mrs"
                    write_yaml(ip_yaml, ips)
                    compile_mrs(ip_yaml, ip_mrs)

def write_yaml(filepath, rules):
    payload = {"payload": rules}
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(payload, f, allow_unicode=True, default_flow_style=False)

def compile_mrs(yaml_path, mrs_path):
    try:
        subprocess.run(['mihomo', 'convert', yaml_path, mrs_path], check=True)
        os.remove(yaml_path)
    except subprocess.CalledProcessError as e:
        print(f"编译失败: {yaml_path} - {e}")

if __name__ == "__main__":
    process_rules()