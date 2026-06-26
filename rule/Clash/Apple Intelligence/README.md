    if has_domain_mrs:
        parts.append(
            f"Domain 规则（必须同时使用）\n"
            f"{cb}text\n"
            f"{RAW_BASE_URL}/{folder_name}/{folder_name}_Domain.mrs\n"
            f"{cb}\n\n"
        )

    if has_ip_mrs:
        parts.append(
            f"IP 规则（必须同时使用）\n"
            f"{cb}text\n"
            f"{RAW_BASE_URL}/{folder_name}/{folder_name}_IP.mrs\n"
            f"{cb}\n\n"
        )

    parts.append(
        f"Classical 规则（单独使用）\n"
        f"{cb}text\n"
        f"{RAW_BASE_URL}/{folder_name}/{classical_filename}\n"
        f"{cb}\n\n"
