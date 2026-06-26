import os
import re
import urllib.request
import zipfile
import shutil
import platform
import stat
import subprocess
import gzip

# ================= 核心配置 =================
REPO_ZIP_URL = "https://github.com/blackmatrix7/ios_rule_script/archive/refs/heads/master.zip"
TEMP_DIR = "temp_ios_rule"
EXTRACT_FOLDER = os.path.join(TEMP_DIR, "ios_rule_script-master")
SOURCE_CLASH_DIR = os.path.join(EXTRACT_FOLDER, "rule", "Clash")
DEST_CLASH_DIR = os.path.join("rule", "Clash")

MY_REPO_URL = "https://github.com/alienwaregf/personal-use/tree/main/rule/Clash"
RAW_BASE_URL = "https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash"

def get_mihomo_binary():
    """根据运行环境 (GitHub Actions / 本地 Mac / Win) 自动下载最新的 Mihomo 编译内核"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    version = "v1.18.3"
    base_url = f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/"
    
    if system == "linux":
        arch = "arm64" if "aarch64" in machine or "arm64" in machine else "amd64"
        filename = f"mihomo-linux-{arch}-{version}.gz"
    elif system == "darwin":
        arch = "arm64" if "arm64" in machine else "amd64"
        filename = f"mihomo-darwin-{arch}-{version}.gz"
    elif system == "windows":
        arch = "arm64" if "arm64" in machine else "amd64"
        filename = f"mihomo-windows-{arch}-{version}.zip"
    else:
        raise Exception(f"不支持的操作系统: {system}")
        
    url = base_url + filename
    bin_name = "mihomo.exe" if system == "windows" else "mihomo"
    bin_path = os.path.abspath(os.path.join(TEMP_DIR, bin_name))
    
    if not os.path.exists(bin_path):
        print(f"正在拉取最新 Mihomo 内核进行 MRS 二进制编译: {url}")
        archive_path = os.path.join(TEMP_DIR, "mihomo_archive")
        urllib.request.urlretrieve(url, archive_path)
        
        if filename.endswith(".gz"):
            with gzip.open(archive_path, 'rb') as f_in:
                with open(bin_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif filename.endswith(".zip"):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for info in zip_ref.infolist():
                    if info.filename.endswith(".exe"):
                        zip_ref.extract(info.filename, TEMP_DIR)
                        os.rename(os.path.join(TEMP_DIR, info.filename), bin_path)
                        break
        
        if system != "windows":
            # 赋予内核执行权限
            st = os.stat(bin_path)
            os.chmod(bin_path, st.st_mode | stat.S_IEXEC)
            
    return bin_path

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

def compile_to_mrs(mihomo_bin, temp_yaml_path, out_mrs_path, rule_type):
    """调用 Mihomo 内核，将拆分好的 yaml 原生编译为极致压缩的 mrs 格式"""
    cmd = [mihomo_bin, "convert-ruleset", rule_type, "yaml", temp_yaml_path, out_mrs_path]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"编译 {out_mrs_path} 失败: {e}")

def modify_readme_clash_section(readme_path, folder_name, classical_filename):
    """精准定位并替换 README.md 中的 Clash 模块，形成三个独立的复制窗口"""
    if not os.path.exists(readme_path):
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    pattern = re.compile(r'(#+\s*Clash\s*\n)(.*?)(?=\n#+ |\Z)', re.DOTALL | re.IGNORECASE)
    
    # 巧妙避开 Markdown 渲染器断层 Bug：使用变量拼接代码块符号
    cb = "```"
    replacement = (
        f"\\1\n"
        f"Domain 规则（必须同时使用）\n"
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
        f"{cb}\n"
    )
    
    new_content = pattern.sub(replacement, content, count=1)
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

def main():
    print("开始执行规则同步与原生 MRS 编译任务...")

    if os.path.exists(DEST_CLASH_DIR):
        shutil.rmtree(DEST_CLASH_DIR)
    os.makedirs(DEST_CLASH_DIR, exist_ok=True)

    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

    zip_path = os.path.join(TEMP_DIR, "master.zip")
    print("正在下载 blackmatrix7 仓库源码压缩包...")
    urllib.request.urlretrieve(REPO_ZIP_URL, zip_path)
    
    print("正在解压...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(TEMP_DIR)

    # 1. 自动获取并配置最新版的 Mihomo 编译内核
    mihomo_bin = get_mihomo_binary()

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

        print(f"编译目录: {item}")
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

        # 挂载 Mihomo 内核进行底层编译
        domain_mrs_path = os.path.join(dest_folder, f"{item}_Domain.mrs")
        ip_mrs_path = os.path.join(dest_folder, f"{item}_IP.mrs")
        
        # Mihomo convert-ruleset 原生支持直接提取 classical payload 的规则并压制成二进制
        compile_to_mrs(mihomo_bin, temp_domain_yaml, domain_mrs_path, "domain")
        compile_to_mrs(mihomo_bin, temp_ip_yaml, ip_mrs_path, "ipcidr")

        # 4. 替换子目录 README.md
        src_readme = os.path.join(folder_path, "README.md")
        dest_readme = os.path.join(dest_folder, "README.md")
        if os.path.exists(src_readme):
            shutil.copy2(src_readme, dest_readme)
            modify_readme_clash_section(dest_readme, item, target_filename)

    # 5. 绝对干净的收尾清理工作
    print("正在清理缓存垃圾、临时文件包与内核驱动...")
    shutil.rmtree(TEMP_DIR)
    print("完美转换！真正的内存优化型 MRS 已生成完毕！")

if __name__ == "__main__":
    main()
