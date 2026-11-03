#!/usr/bin/env python3


from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import random
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import requests
import yaml

SOURCES = [
    ("ripaojiedian", "ripaojiedian/freenode",
     "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash"),
    ("shaoyouvip", "shaoyouvip/free",
     "https://raw.githubusercontent.com/shaoyouvip/free/main/mihomo.yaml"),
    ("lagzian", "lagzian/SS-Collector",
     "https://raw.githubusercontent.com/lagzian/SS-Collector/main/configs/subscription-all.b64"),
    ("clashfree", "free-nodes/clashfree",
     "https://raw.githubusercontent.com/free-nodes/clashfree/main/sub.yml"),
    ("jsnzkpg", "Jsnzkpg/Jsnzkpg",
     "https://raw.githubusercontent.com/Jsnzkpg/Jsnzkpg/Jsnzkpg/Jsnzkpg"),
    ("psg-mix", "itsyebekhe/PSG subscriptions/xray/mix",
     "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix"),
    ("chromego", "Misaka-blog/chromego_merge",
     "https://raw.githubusercontent.com/Misaka-blog/chromego_merge/main/sub/merged_proxies_new.yaml"),
    ("free18", "free18/v2ray",
     "https://raw.githubusercontent.com/free18/v2ray/main/v.txt"),
    ("nomorewalls", "peasoft/NoMoreWalls",
     "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt"),
    ("mahdibland", "mahdibland/V2RayAggregator",
     "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity"),
    ("dafeide", "Dafeide Gist",
     "https://gist.githubusercontent.com/Dafeide/7a072d3de39083d469988844ba2ef165/raw/v2ray"),
]

RAW_BASE = "https://raw.githubusercontent.com/alienwaregf/personal-use/main/proxy/"
STATS_NAME = "Free18_stats.json"
USER_AGENT = "Free18/1.0 (+https://github.com/alienwaregf/personal-use)"

COUNTRY_ZH = {
    "HK": "香港", "TW": "台湾", "MO": "澳门",
    "JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚",
    "TH": "泰国", "ID": "印度尼西亚", "PH": "菲律宾",
    "IN": "印度", "PK": "巴基斯坦", "BD": "孟加拉国", "LK": "斯里兰卡",
    "US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西",
    "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
    "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰",
    "BE": "比利时", "CH": "瑞士", "AT": "奥地利", "SE": "瑞典",
    "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IE": "爱尔兰",
    "ES": "西班牙", "PT": "葡萄牙", "IT": "意大利", "PL": "波兰",
    "CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利", "GR": "希腊",
    "RO": "罗马尼亚", "BG": "保加利亚", "HR": "克罗地亚", "SI": "斯洛文尼亚",
    "UA": "乌克兰", "TR": "土耳其", "IL": "以色列",
    "AE": "阿联酋", "SA": "沙特阿拉伯", "IQ": "伊拉克",
    "EG": "埃及", "ZA": "南非", "NG": "尼日利亚", "KE": "肯尼亚",
    "AU": "澳大利亚", "NZ": "新西兰", "FJ": "斐济",
    "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "IS": "冰岛", "EE": "爱沙尼亚", "LV": "拉脱维亚", "LT": "立陶宛",
    "LU": "卢森堡", "MT": "马耳他", "CY": "塞浦路斯",
    "AC": "阿森松岛", "AD": "安道尔", "AF": "阿富汗", "AG": "安提瓜和巴布达",
    "AI": "安圭拉", "AL": "阿尔巴尼亚", "AM": "亚美尼亚", "AO": "安哥拉",
    "AQ": "南极洲", "AS": "美属萨摩亚", "AW": "阿鲁巴", "AX": "奥兰群岛",
    "AZ": "阿塞拜疆", "BA": "波斯尼亚和黑塞哥维那", "BB": "巴巴多斯",
    "BF": "布基纳法索", "BH": "巴林", "BI": "布隆迪", "BJ": "贝宁",
    "BL": "圣巴泰勒米", "BM": "百慕大", "BN": "文莱", "BO": "玻利维亚",
    "BQ": "荷属加勒比区", "BS": "巴哈马", "BT": "不丹", "BV": "布韦岛",
    "BZ": "伯利兹", "CC": "科科斯（基林）群岛",
    "CD": "刚果（金）", "CF": "中非共和国", "CG": "刚果（布）",
    "CI": "科特迪瓦", "CK": "库克群岛", "CM": "喀麦隆",
    "CP": "克利珀顿岛", "CQ": "萨克岛", "CR": "哥斯达黎加",
    "CV": "佛得角", "CW": "库拉索", "CX": "圣诞岛", "DG": "迪戈加西亚岛",
    "DJ": "吉布提", "DM": "多米尼克", "DO": "多米尼加共和国",
    "DZ": "阿尔及利亚", "EA": "休达及梅利利亚", "EC": "厄瓜多尔",
    "EH": "西撒哈拉", "ER": "厄立特里亚", "ET": "埃塞俄比亚",
    "FK": "福克兰群岛", "FM": "密克罗尼西亚", "FO": "法罗群岛",
    "GA": "加蓬", "GD": "格林纳达", "GE": "格鲁吉亚", "GF": "法属圭亚那",
    "GG": "根西岛", "GH": "加纳", "GI": "直布罗陀", "GL": "格陵兰",
    "GM": "冈比亚", "GN": "几内亚", "GP": "瓜德罗普", "GQ": "赤道几内亚",
    "GS": "南乔治亚和南桑威奇群岛", "GT": "危地马拉", "GU": "关岛",
    "GW": "几内亚比绍", "GY": "圭亚那", "HM": "赫德岛和麦克唐纳群岛",
    "HN": "洪都拉斯", "HT": "海地", "IC": "加纳利群岛", "IM": "马恩岛",
    "IO": "英属印度洋领地", "JE": "泽西岛", "JM": "牙买加", "JO": "约旦",
    "KG": "吉尔吉斯斯坦", "KH": "柬埔寨", "KI": "基里巴斯", "KM": "科摩罗",
    "KN": "圣基茨和尼维斯", "KW": "科威特", "KY": "开曼群岛",
    "LA": "老挝", "LB": "黎巴嫩", "LC": "圣卢西亚", "LI": "列支敦士登",
    "LR": "利比里亚", "LS": "莱索托", "LY": "利比亚", "MA": "摩洛哥",
    "MC": "摩纳哥", "MD": "摩尔多瓦", "ME": "黑山", "MF": "法属圣马丁",
    "MG": "马达加斯加", "MH": "马绍尔群岛", "MK": "北马其顿", "ML": "马里",
    "MN": "蒙古", "MP": "北马里亚纳群岛", "MQ": "马提尼克",
    "MR": "毛里塔尼亚", "MS": "蒙特塞拉特", "MU": "毛里求斯",
    "MV": "马尔代夫", "MW": "马拉维", "MZ": "莫桑比克", "NA": "纳米比亚",
    "NC": "新喀里多尼亚", "NE": "尼日尔", "NF": "诺福克岛",
    "NI": "尼加拉瓜", "NP": "尼泊尔", "NR": "瑙鲁", "NU": "纽埃",
    "OM": "阿曼", "PA": "巴拿马", "PF": "法属波利尼西亚",
    "PG": "巴布亚新几内亚", "PM": "圣皮埃尔和密克隆群岛",
    "PN": "皮特凯恩群岛", "PR": "波多黎各", "PS": "巴勒斯坦", "PW": "帕劳",
    "PY": "巴拉圭", "QA": "卡塔尔", "RE": "留尼汪", "RS": "塞尔维亚",
    "RW": "卢旺达", "SB": "所罗门群岛", "SC": "塞舌尔", "SD": "苏丹",
    "SH": "圣赫勒拿", "SJ": "斯瓦尔巴和扬马延", "SL": "塞拉利昂",
    "SM": "圣马力诺", "SN": "塞内加尔", "SO": "索马里", "SR": "苏里南",
    "SS": "南苏丹", "ST": "圣多美和普林西比", "SV": "萨尔瓦多",
    "SX": "荷属圣马丁", "SY": "叙利亚", "SZ": "斯威士兰",
    "TA": "特里斯坦-达库尼亚群岛", "TC": "特克斯和凯科斯群岛",
    "TD": "乍得", "TF": "法属南部领地", "TG": "多哥", "TJ": "塔吉克斯坦",
    "TK": "托克劳", "TL": "东帝汶", "TN": "突尼斯",
    "TO": "汤加", "TT": "特立尼达和多巴哥", "TV": "图瓦卢", "TZ": "坦桑尼亚",
    "UG": "乌干达", "UM": "美国本土外小岛屿", "UY": "乌拉圭", "VA": "梵蒂冈",
    "VC": "圣文森特和格林纳丁斯", "VE": "委内瑞拉",
    "VG": "英属维尔京群岛", "VI": "美属维尔京群岛", "VU": "瓦努阿图",
    "WF": "瓦利斯和富图纳", "WS": "萨摩亚", "XK": "科索沃", "YE": "也门",
    "YT": "马约特", "ZM": "赞比亚", "ZW": "津巴布韦",
}

GFW_COUNTRIES = frozenset({"CN", "KP", "IR", "TM", "RU", "BY", "CU", "VN", "MM"})

COUNTRY_CAP = 10
COUNTRY_CAP_EXEMPT = frozenset({"US"})
COUNTRY_CAP_SEED = "Free18"

CF_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "2400:cb00::/32", "2405:8100::/32", "2405:b500::/32",
    "2606:4700::/32", "2803:f800::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
))

LINK_SCHEMES = (
    "vmess://", "vless://", "trojan://", "ss://", "ssr://",
    "hysteria2://", "hy2://", "hysteria://", "tuic://",
    "socks://", "socks5://", "http://", "https://",
)
SUPERSCRIPTS = "¹²³⁴⁵⁶⁷⁸⁹"


def b64decode_loose(text):
    s = re.sub(r"\s+", "", text.strip())
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, ValueError):
        return base64.b64decode(s)


def b64encode_std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64encode_url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def flag_emoji(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_cloudflare_ip(server: str) -> bool:
    try:
        addr = ipaddress.ip_address((server or "").strip().strip("[]").lower())
    except ValueError:
        return False
    return any(addr in net for net in CF_NETWORKS)


def norm_server(server: str) -> str:
    return (server or "").strip().strip("[]").lower()


def parse_port(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def split_hostport(netloc: str):
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            return netloc, None
        host = netloc[1:end]
        rest = netloc[end + 1:]
        port = parse_port(rest[1:]) if rest.startswith(":") else None
        return host, port
    if netloc.count(":") == 1:
        host, _, port_s = netloc.partition(":")
        return host, parse_port(port_s)
    return netloc, None


def query_dict(pairs) -> dict:
    out = {}
    for key, val in pairs:
        out[key] = val
    return out


def boolish(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off", ""):
        return False
    return None


def to_int(value) -> int | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def new_node(ntype: str) -> dict:
    return {
        "type": ntype, "server": "", "port": None, "name_orig": "",
        "uuid": None, "password": None, "username": None,
        "cipher": None, "alter_id": None,
        "network": None, "header_type": None,
        "path": None, "host": None, "service_name": None,
        "tls": False, "sni": None, "alpn": None, "fp": None,
        "skip_cert_verify": None,
        "flow": None, "encryption": None, "security": None,
        "pbk": None, "sid": None,
        "plugin": None, "plugin_opts": {},
        "ssr_protocol": None, "ssr_protocol_param": None,
        "ssr_obfs": None, "ssr_obfs_param": None,
        "hy2_obfs": None, "hy2_obfs_password": None, "mport": None,
        "hy2_up": None, "hy2_down": None,
        "tuic_congestion": None, "tuic_udp_relay": None,
        "tuic_reduce_rtt": None, "tuic_max_udp": None,
        "hy1_auth": None, "hy1_protocol": None, "hy1_up": None,
        "hy1_down": None, "hy1_obfs": None,
        "http_method": None, "http_headers": None,
        "packet_encoding": None,
        "query": None, "ss_query": None, "ssr_params": None,
        "vmess_json": None, "yaml_dict": None,
    }


def _uri_parts(link: str):
    parts = urlsplit(link)
    raw_netloc = parts.netloc
    if "@" in raw_netloc:
        userinfo, _, hostport = raw_netloc.rpartition("@")
    else:
        userinfo, hostport = "", raw_netloc
    host, port = split_hostport(hostport)
    query = query_dict(parse_qsl(parts.query, keep_blank_values=True))
    name = unquote(parts.fragment) if parts.fragment else ""
    return userinfo, host, port, query, name


def parse_vmess_link(link: str):
    try:
        payload = b64decode_loose(link[len("vmess://"):].split("#")[0])
        data = json.loads(payload.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("add") or not data.get("id"):
        return None
    node = new_node("vmess")
    node["server"] = norm_server(str(data.get("add", "")))
    node["port"] = parse_port(data.get("port"))
    node["uuid"] = str(data.get("id", "")).strip()
    node["cipher"] = str(data.get("scy", "") or "").strip() or None
    node["alter_id"] = to_int(data.get("aid"))
    node["network"] = str(data.get("net", "") or "").strip().lower() or None
    node["header_type"] = str(data.get("type", "") or "").strip() or None
    node["host"] = str(data.get("host", "") or "").strip() or None
    node["path"] = str(data.get("path", "") or "").strip() or None
    node["tls"] = str(data.get("tls", "")).strip().lower() == "tls"
    node["sni"] = str(data.get("sni", "") or "").strip() or None
    alpn = data.get("alpn")
    node["alpn"] = [str(a).strip() for a in alpn] if isinstance(alpn, list) else (
        [a.strip() for a in str(alpn).split(",") if a.strip()] if alpn else None)
    node["fp"] = str(data.get("fp", "") or "").strip() or None
    node["name_orig"] = str(data.get("ps", "") or "")
    extra = {k: v for k, v in data.items()
             if k not in ("v", "ps", "add", "port", "id", "aid", "scy",
                          "net", "type", "host", "path", "tls", "sni",
                          "alpn", "fp")}
    node["vmess_json"] = extra
    return node


def parse_query_link(link: str, ntype: str):
    userinfo, host, port, query, name = _uri_parts(link)
    node = new_node(ntype)
    node["server"] = norm_server(host)
    node["port"] = port
    node["name_orig"] = name
    node["query"] = query
    if "@" in userinfo or ":" in userinfo:
        user, _, pwd = userinfo.partition(":")
        node["username"] = unquote(user) or None
        node["password"] = unquote(pwd) or None
    else:
        node["username"] = unquote(userinfo) or None
    return node, query


def parse_vless_link(link: str):
    node, query = parse_query_link(link, "vless")
    node["uuid"] = node.pop("username")
    node["password"] = None
    node["flow"] = query.get("flow") or None
    node["encryption"] = query.get("encryption") or None
    node["security"] = query.get("security") or None
    node["network"] = (query.get("type") or query.get("network") or "").lower() or None
    node["header_type"] = query.get("headerType") or None
    node["path"] = unquote(query["path"]) if "path" in query else None
    node["host"] = query.get("host") or None
    node["service_name"] = query.get("serviceName") or query.get("servicename") or None
    node["sni"] = query.get("sni") or query.get("peer") or query.get("servername") or None
    node["fp"] = query.get("fp") or None
    node["pbk"] = query.get("pbk") or None
    node["sid"] = query.get("sid") or None
    alpn = query.get("alpn")
    node["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()] if alpn else None
    node["tls"] = node["security"] in ("tls", "reality", "xtls")
    node["packet_encoding"] = query.get("packetEncoding") or None
    return node


def parse_trojan_link(link: str):
    node, query = parse_query_link(link, "trojan")
    node["password"] = node.pop("username")
    node["username"] = None
    node["security"] = query.get("security") or None
    node["network"] = (query.get("type") or query.get("network") or "").lower() or None
    node["header_type"] = query.get("headerType") or None
    node["path"] = unquote(query["path"]) if "path" in query else None
    node["host"] = query.get("host") or None
    node["service_name"] = query.get("serviceName") or query.get("servicename") or None
    node["sni"] = query.get("sni") or query.get("peer") or query.get("servername") or None
    node["fp"] = query.get("fp") or None
    node["pbk"] = query.get("pbk") or None
    node["sid"] = query.get("sid") or None
    alpn = query.get("alpn")
    node["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()] if alpn else None
    node["tls"] = True
    return node


def _parse_ss_plugin(query: dict, node: dict):
    raw_plugin = query.get("plugin", "")
    if not raw_plugin:
        return
    plugin = unquote(raw_plugin)
    parts = plugin.split(";")
    node["plugin"] = parts[0].strip()
    opts = {}
    for piece in parts[1:]:
        if "=" in piece:
            key, _, val = piece.partition("=")
            opts[key.strip()] = val.strip()
        elif piece.strip():
            opts[piece.strip()] = True
    node["plugin_opts"] = opts


def parse_ss_link(link: str):
    rest = link[len("ss://"):]
    name = ""
    if "#" in rest:
        rest, _, name = rest.partition("#")
        name = unquote(name)
    query = {}
    if "?" in rest:
        rest, _, qstr = rest.partition("?")
        query = query_dict(parse_qsl(qstr, keep_blank_values=True))
    node = new_node("ss")
    node["name_orig"] = name
    node["ss_query"] = query
    _parse_ss_plugin(query, node)
    userinfo_hostport = rest
    if "@" in rest:
        userinfo, _, hostport = rest.rpartition("@")
        hostport = hostport.rstrip("/")
        host, port = split_hostport(hostport)
        try:
            decoded = b64decode_loose(userinfo).decode("utf-8")
            if ":" in decoded:
                method, _, password = decoded.partition(":")
            else:
                raise ValueError("no colon in decoded ss userinfo")
        except Exception:
            method, _, password = unquote(userinfo).partition(":")
            password = unquote(password)
        node["cipher"] = method.strip() or None
        node["password"] = password
        node["server"] = norm_server(host)
        node["port"] = port
        return node
    try:
        decoded = b64decode_loose(rest).decode("utf-8")
    except Exception:
        return None
    if "@" not in decoded or ":" not in decoded:
        return None
    left, _, hostport = decoded.rpartition("@")
    method, _, password = left.partition(":")
    host, port = split_hostport(hostport.rstrip("/"))
    node["cipher"] = method.strip() or None
    node["password"] = password
    node["server"] = norm_server(host)
    node["port"] = port
    return node


def parse_ssr_link(link: str):
    try:
        decoded = b64decode_loose(link[len("ssr://"):]).decode("utf-8")
    except Exception:
        return None
    main, _, qstr = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) != 6:
        return None
    host, port_s, protocol, method, obfs, pwd_b64 = parts
    try:
        password = b64decode_loose(pwd_b64).decode("utf-8")
    except Exception:
        return None
    params = query_dict(parse_qsl(qstr, keep_blank_values=True)) if qstr else {}
    node = new_node("ssr")
    node["server"] = norm_server(host)
    node["port"] = parse_port(port_s)
    node["cipher"] = method or None
    node["password"] = password
    node["ssr_protocol"] = protocol or None
    node["ssr_obfs"] = obfs or None
    node["ssr_params"] = params

    def _dec(key):
        val = params.get(key)
        if not val:
            return None
        try:
            return b64decode_loose(val).decode("utf-8")
        except Exception:
            return val
    node["ssr_protocol_param"] = _dec("protoparam")
    node["ssr_obfs_param"] = _dec("obfsparam")
    node["name_orig"] = _dec("remarks") or ""
    return node


def parse_hy2_link(link: str):
    node, query = parse_query_link(link, "hysteria2")
    node["password"] = node.pop("username")
    node["username"] = None
    node["sni"] = query.get("sni") or query.get("peer") or None
    node["skip_cert_verify"] = boolish(query.get("insecure") or query.get("allowInsecure"))
    node["hy2_obfs"] = query.get("obfs") or None
    node["hy2_obfs_password"] = query.get("obfs-password") or query.get("obfs_password") or None
    alpn = query.get("alpn")
    node["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()] if alpn else None
    node["mport"] = query.get("mport") or None
    node["hy2_up"] = to_int(query.get("up"))
    node["hy2_down"] = to_int(query.get("down"))
    node["fp"] = query.get("fp") or None
    node["tls"] = True
    return node


def parse_hysteria_link(link: str):
    node, query = parse_query_link(link, "hysteria")
    node["hy1_auth"] = query.get("auth") or query.get("auth_str") or node.pop("username")
    node["username"] = None
    node["hy1_protocol"] = query.get("protocol") or None
    node["hy1_up"] = to_int(query.get("up"))
    node["hy1_down"] = to_int(query.get("down"))
    node["hy1_obfs"] = query.get("obfs") or None
    node["sni"] = query.get("sni") or query.get("peer") or None
    node["skip_cert_verify"] = boolish(query.get("insecure") or query.get("allowInsecure"))
    alpn = query.get("alpn")
    node["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()] if alpn else None
    node["fp"] = query.get("fp") or None
    node["tls"] = True
    return node


def parse_tuic_link(link: str):
    node, query = parse_query_link(link, "tuic")
    node["uuid"] = node["username"]
    node["username"] = None
    node["sni"] = query.get("sni") or query.get("peer") or None
    node["skip_cert_verify"] = boolish(
        query.get("allow-insecure") or query.get("allowInsecure"))
    alpn = query.get("alpn")
    node["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()] if alpn else None
    node["tuic_congestion"] = (
        query.get("congestion-control") or query.get("congestion_control") or None)
    node["tuic_udp_relay"] = (
        query.get("udp-relay-mode") or query.get("udp_relay_mode") or None)
    node["tuic_reduce_rtt"] = boolish(query.get("reduce-rtt") or query.get("reduce_rtt"))
    node["tuic_max_udp"] = to_int(
        query.get("max-udp-relay-packet-size") or query.get("max_udp_relay_packet_size"))
    node["fp"] = query.get("fp") or None
    node["tls"] = True
    return node


def parse_socks_link(link: str):
    node, query = parse_query_link(link, "socks5")
    node["tls"] = link.startswith("socks5-tls://") or boolish(query.get("tls")) or False
    node["sni"] = query.get("sni") or None
    node["skip_cert_verify"] = boolish(query.get("insecure") or query.get("allowInsecure"))
    return node


def parse_http_link(link: str):
    node, query = parse_query_link(link, "http")
    node["tls"] = link.startswith("https://")
    node["sni"] = query.get("sni") or None
    node["skip_cert_verify"] = boolish(query.get("insecure") or query.get("allowInsecure"))
    return node


def parse_link(line: str):
    line = line.strip()
    if not line:
        return None
    low = line.lower()
    try:
        if low.startswith("vmess://"):
            node = parse_vmess_link(line)
        elif low.startswith("vless://"):
            node = parse_vless_link(line)
        elif low.startswith("trojan://"):
            node = parse_trojan_link(line)
        elif low.startswith("ss://"):
            node = parse_ss_link(line)
        elif low.startswith("ssr://"):
            node = parse_ssr_link(line)
        elif low.startswith(("hysteria2://", "hy2://")):
            node = parse_hy2_link(line)
        elif low.startswith("hysteria://"):
            node = parse_hysteria_link(line)
        elif low.startswith("tuic://"):
            node = parse_tuic_link(line)
        elif low.startswith(("socks://", "socks5://", "socks5-tls://")):
            node = parse_socks_link(line)
        elif low.startswith(("http://", "https://")):
            node = parse_http_link(line)
        else:
            return None
    except Exception:
        return None
    if node is None or not node.get("server") or not node.get("port"):
        return None
    return node


def node_complete(node: dict) -> bool:
    return bool(node.get("server")) and bool(node.get("port"))


def _alpn_list(value):
    if value is None:
        return None
    if isinstance(value, list):
        return [str(a).strip() for a in value if str(a).strip()]
    return [a.strip() for a in str(value).split(",") if a.strip()]


def _transport_from_yaml(node: dict, data: dict):
    network = str(data.get("network", "") or "").strip().lower() or None
    node["network"] = network
    ws_opts = data.get("ws-opts") or {}
    if isinstance(ws_opts, dict):
        node["path"] = ws_opts.get("path") or node["path"]
        headers = ws_opts.get("headers") or {}
        if isinstance(headers, dict):
            node["host"] = headers.get("Host") or headers.get("host") or node["host"]
    http_opts = data.get("http-opts") or {}
    if isinstance(http_opts, dict):
        node["http_method"] = http_opts.get("method") or None
        node["path"] = http_opts.get("path") or node["path"]
        headers = http_opts.get("headers") or {}
        if isinstance(headers, dict):
            node["http_headers"] = dict(headers)
            node["host"] = headers.get("Host") or headers.get("host") or node["host"]
    h2_opts = data.get("h2-opts") or {}
    if isinstance(h2_opts, dict):
        hosts = h2_opts.get("host")
        if isinstance(hosts, list) and hosts:
            node["host"] = str(hosts[0])
        elif hosts:
            node["host"] = str(hosts)
        node["path"] = h2_opts.get("path") or node["path"]
    grpc_opts = data.get("grpc-opts") or {}
    if isinstance(grpc_opts, dict):
        node["service_name"] = grpc_opts.get("grpc-service-name") or None
    xhttp_opts = data.get("xhttp-opts") or {}
    if isinstance(xhttp_opts, dict):
        node["path"] = xhttp_opts.get("path") or node["path"]
        node["host"] = xhttp_opts.get("host") or node["host"]
        node["service_name"] = xhttp_opts.get("mode") or node["service_name"]


def yaml_to_neutral(data: dict):
    if not isinstance(data, dict):
        return None
    raw_type = str(data.get("type", "") or "").strip().lower()
    type_map = {
        "vmess": "vmess", "vless": "vless", "trojan": "trojan",
        "ss": "ss", "shadowsocks": "ss", "ssr": "ssr",
        "shadowsocksr": "ssr", "hysteria2": "hysteria2", "hy2": "hysteria2",
        "hysteria": "hysteria", "tuic": "tuic",
        "socks5": "socks5", "socks": "socks5",
        "http": "http", "https": "http",
    }
    ntype = type_map.get(raw_type)
    if ntype is None:
        return None
    node = new_node(ntype)
    node["yaml_dict"] = dict(data)
    node["server"] = norm_server(str(data.get("server", "")))
    node["port"] = parse_port(data.get("port"))
    node["name_orig"] = str(data.get("name", "") or "")
    node["uuid"] = str(data.get("uuid", "") or "").strip() or None
    node["password"] = str(data.get("password", "") or "") or None
    node["username"] = str(data.get("username", "") or "") or None
    node["cipher"] = str(data.get("cipher", "") or "").strip() or None
    node["alter_id"] = to_int(data.get("alterId"))
    node["tls"] = boolish(data.get("tls")) or False
    node["sni"] = str(data.get("sni") or data.get("servername") or "") or None
    node["alpn"] = _alpn_list(data.get("alpn"))
    node["fp"] = str(data.get("fingerprint") or data.get("client-fingerprint") or "") or None
    node["skip_cert_verify"] = boolish(data.get("skip-cert-verify"))
    node["flow"] = str(data.get("flow", "") or "") or None
    node["packet_encoding"] = str(data.get("packet-encoding", "") or "") or None
    reality = data.get("reality-opts") or {}
    if isinstance(reality, dict):
        node["pbk"] = str(reality.get("public-key", "") or "") or None
        node["sid"] = str(reality.get("short-id", "") or "") or None
        node["security"] = "reality"
    elif node["tls"]:
        node["security"] = "tls"
    _transport_from_yaml(node, data)
    if ntype == "ss":
        plugin = data.get("plugin")
        if plugin:
            node["plugin"] = str(plugin)
        opts = data.get("plugin-opts") or {}
        if isinstance(opts, dict):
            node["plugin_opts"] = {str(k): str(v) for k, v in opts.items()}
    if ntype == "ssr":
        node["ssr_protocol"] = str(data.get("protocol", "") or "") or None
        node["ssr_protocol_param"] = str(data.get("protocol-param", "") or "") or None
        node["ssr_obfs"] = str(data.get("obfs", "") or "") or None
        node["ssr_obfs_param"] = str(data.get("obfs-param", "") or "") or None
    if ntype == "hysteria2":
        node["hy2_obfs"] = str(data.get("obfs", "") or "") or None
        node["hy2_obfs_password"] = str(data.get("obfs-password", "") or "") or None
        node["hy2_up"] = to_int(data.get("up"))
        node["hy2_down"] = to_int(data.get("down"))
        ports = data.get("ports")
        node["mport"] = str(ports) if ports else None
    if ntype == "tuic":
        node["tuic_congestion"] = str(data.get("congestion-controller", "") or "") or None
        node["tuic_udp_relay"] = str(data.get("udp-relay-mode", "") or "") or None
        node["tuic_reduce_rtt"] = boolish(data.get("reduce-rtt"))
    if ntype == "hysteria":
        node["hy1_auth"] = str(data.get("auth_str") or data.get("authStr")
                               or data.get("auth") or "") or None
        node["hy1_protocol"] = str(data.get("protocol", "") or "") or None
        node["hy1_up"] = to_int(data.get("up"))
        node["hy1_down"] = to_int(data.get("down"))
        node["hy1_obfs"] = str(data.get("obfs", "") or "") or None
    if ntype == "http":
        node["tls"] = raw_type == "https" or boolish(data.get("tls")) or False
    return node


def singbox_to_neutral(data: dict):
    if not isinstance(data, dict):
        return None
    raw_type = str(data.get("type", "") or "").strip().lower()
    type_map = {
        "vmess": "vmess", "vless": "vless", "trojan": "trojan",
        "shadowsocks": "ss", "shadowsocksr": "ssr", "hysteria2": "hysteria2",
        "hysteria": "hysteria", "tuic": "tuic", "socks": "socks5",
        "http": "http",
    }
    ntype = type_map.get(raw_type)
    if ntype is None:
        return None
    node = new_node(ntype)
    node["server"] = norm_server(str(data.get("server", "")))
    node["port"] = parse_port(data.get("server_port"))
    node["name_orig"] = str(data.get("tag", "") or "")
    node["uuid"] = str(data.get("uuid", "") or "") or None
    node["password"] = str(data.get("password", "") or "") or None
    node["username"] = str(data.get("username", "") or "") or None
    node["cipher"] = str(data.get("method", "") or "") or None
    node["alter_id"] = to_int(data.get("alter_id"))
    transport = data.get("transport") or {}
    if isinstance(transport, dict):
        node["network"] = str(transport.get("type", "") or "").lower() or None
        node["path"] = transport.get("path") or None
        headers = transport.get("headers") or {}
        if isinstance(headers, dict):
            node["host"] = headers.get("Host") or headers.get("host") or None
        node["service_name"] = transport.get("service_name") or None
        node["http_method"] = transport.get("method") or None
    tls = data.get("tls") or {}
    if isinstance(tls, dict) and tls.get("enabled"):
        node["tls"] = True
        node["sni"] = str(tls.get("server_name", "") or "") or None
        node["alpn"] = _alpn_list(tls.get("alpn"))
        node["skip_cert_verify"] = boolish(tls.get("insecure"))
        utls = tls.get("utls") or {}
        if isinstance(utls, dict):
            node["fp"] = str(utls.get("fingerprint", "") or "") or None
        reality = tls.get("reality") or {}
        if isinstance(reality, dict) and reality.get("enabled"):
            node["pbk"] = str(reality.get("public_key", "") or "") or None
            node["sid"] = str(reality.get("short_id", "") or "") or None
            node["security"] = "reality"
    if ntype == "ssr":
        node["ssr_protocol"] = str(data.get("protocol", "") or "") or None
        node["ssr_protocol_param"] = str(data.get("protocol_param", "") or "") or None
        node["ssr_obfs"] = str(data.get("obfs", "") or "") or None
        node["ssr_obfs_param"] = str(data.get("obfs_param", "") or "") or None
    if ntype == "hysteria2":
        node["hy2_obfs"] = str(data.get("obfs", {}).get("type", "") or "") or None
        obfs = data.get("obfs") or {}
        if isinstance(obfs, dict):
            node["hy2_obfs_password"] = str(obfs.get("password", "") or "") or None
        node["hy2_up"] = to_int(data.get("up_mbps"))
        node["hy2_down"] = to_int(data.get("down_mbps"))
    if ntype == "tuic":
        node["tuic_congestion"] = str(data.get("congestion_control", "") or "") or None
        node["tuic_udp_relay"] = str(data.get("udp_relay_mode", "") or "") or None
        node["tuic_reduce_rtt"] = boolish(data.get("reduce_rtt"))
    return node


def parse_content(text: str):
    nodes = []
    stripped = text.strip().lstrip("\ufeff")
    if not stripped:
        return nodes, "empty"
    blob = re.sub(r"\s+", "", stripped)
    if len(blob) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", blob):
        try:
            decoded = b64decode_loose(blob).decode("utf-8")
            if any(s in decoded for s in ("://", "proxies:", "outbounds")):
                inner_nodes, inner_kind = parse_content(decoded)
                if inner_nodes:
                    return inner_nodes, "base64+" + inner_kind
        except Exception:
            pass
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except Exception:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("outbounds"), list):
            for item in doc["outbounds"]:
                node = singbox_to_neutral(item)
                if node and node_complete(node):
                    nodes.append(node)
            if nodes:
                return nodes, "singbox-json"
    try:
        doc = yaml.safe_load(stripped)
    except Exception:
        doc = None
    if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
        for item in doc["proxies"]:
            node = yaml_to_neutral(item)
            if node and node_complete(node):
                nodes.append(node)
        if nodes:
            return nodes, "clash-yaml"
    if isinstance(doc, list):
        for item in doc:
            node = yaml_to_neutral(item)
            if node and node_complete(node):
                nodes.append(node)
        if nodes:
            return nodes, "yaml-list"
    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_link(line)
        if node is None and re.fullmatch(r"[A-Za-z0-9+/=_-]+", line) and len(line) >= 20:
            try:
                decoded = b64decode_loose(line).decode("utf-8").strip()
            except Exception:
                decoded = ""
            if decoded:
                node = parse_link(decoded)
                if node is None and decoded.startswith("{"):
                    try:
                        vm = json.loads(decoded)
                    except Exception:
                        vm = None
                    if isinstance(vm, dict) and vm.get("add") and vm.get("id"):
                        node = parse_vmess_link(
                            "vmess://" + b64encode_std(decoded.encode("utf-8")))
        if node is not None:
            nodes.append(node)
    return nodes, "link-lines"


def dedupe_key(node: dict):
    drop = {"name", "name_orig", "yaml_dict", "_geo",
            "uuid", "password", "hy1_auth", "username", "hy2_obfs_password"}
    cred_keys = {"uuid", "password", "passwd", "pwd", "auth", "auth_str",
                 "token", "obfs-password", "obfs_password", "id", "key",
                 "secret"}

    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()
                    if str(k).lower() not in cred_keys}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value

    rest = {k: clean(v) for k, v in node.items() if k not in drop}
    rest["server"] = norm_server(node["server"])
    return json.dumps(rest, sort_keys=True, ensure_ascii=False, default=str)


def dedupe(nodes):
    seen = {}
    duplicates = 0
    for node in nodes:
        key = dedupe_key(node)
        if key in seen:
            duplicates += 1
            continue
        seen[key] = node
    return list(seen.values()), duplicates


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def _transport_opts(node: dict):
    network = (node.get("network") or "tcp").lower()
    return network, node.get("path"), node.get("host"), node.get("service_name")


def _fix_mihomo_opts(data: dict) -> dict:
    opts = data.get("http-opts")
    if isinstance(opts, dict):
        opts = dict(opts)
        headers = opts.get("headers")
        if isinstance(headers, dict):
            opts["headers"] = {k: ([v] if isinstance(v, str) else v)
                               for k, v in headers.items()}
        if isinstance(opts.get("path"), str):
            opts["path"] = [opts["path"]]
        data["http-opts"] = opts
    opts = data.get("ws-opts")
    if isinstance(opts, dict):
        opts = dict(opts)
        headers = opts.get("headers")
        if isinstance(headers, dict):
            fixed = {}
            for k, v in headers.items():
                if isinstance(v, list):
                    fixed[k] = v[0] if v else ""
                else:
                    fixed[k] = v
            opts["headers"] = fixed
        data["ws-opts"] = opts
    opts = data.get("h2-opts")
    if isinstance(opts, dict):
        opts = dict(opts)
        if isinstance(opts.get("host"), str):
            opts["host"] = [opts["host"]]
        path = opts.get("path")
        if isinstance(path, list):
            opts["path"] = path[0] if path else ""
        data["h2-opts"] = opts
    return data


MIHOMO_SS_CIPHERS = frozenset({
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "chacha20-ietf", "chacha20", "xchacha20", "rc4-md5",
})


def _norm_ss_cipher(cipher):
    if not isinstance(cipher, str):
        return None
    c = cipher.strip().lower()
    return c if c in MIHOMO_SS_CIPHERS else None


def _valid_reality_pubkey(key) -> bool:
    if not isinstance(key, str):
        return False
    key = key.strip()
    if len(key) != 43:
        return False
    try:
        raw = base64.urlsafe_b64decode(key + "=")
    except (binascii.Error, ValueError):
        return False
    if len(raw) != 32:
        return False
    return base64.urlsafe_b64encode(raw).decode().rstrip("=") == key


def _valid_reality_sid(sid) -> bool:
    if sid is None:
        return True
    sid = str(sid).strip()
    if not sid:
        return True
    if len(sid) % 2 or len(sid) > 16:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in sid)


def to_mihomo_dict(node: dict, name: str):
    if node.get("type") == "vless":
        flow = node.get("flow")
        if flow and str(flow).strip().lower() != "xtls-rprx-vision":
            return None
    if node.get("yaml_dict") is None and node.get("type") in ("vmess", "vless", "trojan") and node.get("pbk"):
        if not _valid_reality_pubkey(node["pbk"]):
            return None
        if not _valid_reality_sid(node.get("sid")):
            return None
    ss_cipher = None
    if node.get("type") == "ss":
        ss_cipher = _norm_ss_cipher(node.get("cipher"))
        if ss_cipher is None:
            return None
    if node.get("yaml_dict") is not None:
        data = dict(node["yaml_dict"])
        data["name"] = name
        if ss_cipher is not None:
            data["cipher"] = ss_cipher
        if node.get("type") == "vless" and data.get("flow"):
            data["flow"] = "xtls-rprx-vision"
        data = _fix_mihomo_opts(data)
        if node.get("type") in ("vmess", "vless", "trojan"):
            ropts = data.get("reality-opts")
            if isinstance(ropts, dict) and ropts.get("public-key"):
                ropts = dict(ropts)
                ropts["public-key"] = str(ropts["public-key"]).strip()
                if ropts.get("short-id") is not None:
                    ropts["short-id"] = str(ropts["short-id"]).strip()
                data["reality-opts"] = ropts
                if not _valid_reality_pubkey(ropts["public-key"]):
                    return None
                if not _valid_reality_sid(ropts.get("short-id")):
                    return None
        return data
    ntype = node["type"]
    if ntype in ("ssr", "ss", "trojan", "vmess", "vless",
                 "hysteria2", "hysteria", "tuic", "socks5", "http"):
        pass
    else:
        return None
    d = {"name": name, "type": ntype, "server": node["server"],
         "port": node["port"]}
    network, ws_path, ws_host, service_name = _transport_opts(node)
    tls = bool(node.get("tls"))
    if ntype == "vmess":
        d["uuid"] = node["uuid"]
        d["alterId"] = node["alter_id"] if node["alter_id"] is not None else 0
        d["cipher"] = node["cipher"] or "auto"
        if tls:
            d["tls"] = True
        if node.get("sni"):
            d["servername"] = node["sni"]
        if node.get("alpn"):
            d["alpn"] = list(node["alpn"])
        if node.get("fp"):
            d["fingerprint"] = node["fp"]
        if node.get("skip_cert_verify") is not None:
            d["skip-cert-verify"] = bool(node["skip_cert_verify"])
        if network == "ws":
            opts = _clean({"path": ws_path, "headers": (
                {"Host": ws_host} if ws_host else None)})
            d["network"] = "ws"
            d["ws-opts"] = opts
        elif network == "tcp" and (node.get("header_type") or "").lower() == "http":
            d["network"] = "tcp"
            d["http-opts"] = _clean({
                "method": node.get("http_method") or "GET",
                "path": [ws_path] if ws_path else None,
                "headers": ({"Host": ([ws_host] if isinstance(ws_host, str)
                                      else ws_host)} if ws_host else None)})
        elif network == "h2":
            d["network"] = "h2"
            d["h2-opts"] = _clean({"host": [ws_host] if ws_host else None,
                                   "path": ws_path})
        elif network == "grpc":
            d["network"] = "grpc"
            d["grpc-opts"] = {"grpc-service-name": service_name or ""}
        elif network in ("tcp",):
            d["network"] = "tcp"
        else:
            return None
        if node.get("pbk"):
            d["reality-opts"] = _clean({"public-key": node["pbk"],
                                        "short-id": node["sid"] or ""})
    elif ntype == "vless":
        d["uuid"] = node["uuid"]
        if node.get("flow"):
            d["flow"] = "xtls-rprx-vision"
        if tls:
            d["tls"] = True
        if node.get("sni"):
            d["servername"] = node["sni"]
        if node.get("alpn"):
            d["alpn"] = list(node["alpn"])
        if node.get("fp"):
            d["fingerprint"] = node["fp"]
        if node.get("skip_cert_verify") is not None:
            d["skip-cert-verify"] = bool(node["skip_cert_verify"])
        if node.get("packet_encoding") in ("packetaddr", "xudp", "none"):
            d["packet-encoding"] = node["packet_encoding"]
        if network == "ws":
            d["network"] = "ws"
            d["ws-opts"] = _clean({"path": ws_path, "headers": (
                {"Host": ws_host} if ws_host else None)})
        elif network == "grpc":
            d["network"] = "grpc"
            d["grpc-opts"] = {"grpc-service-name": service_name or ""}
        elif network == "h2":
            d["network"] = "h2"
            d["h2-opts"] = _clean({"host": [ws_host] if ws_host else None,
                                   "path": ws_path})
        elif network in ("tcp", "http"):
            d["network"] = network
            if network == "http":
                d["http-opts"] = _clean({
                    "method": node.get("http_method") or "GET",
                    "path": [ws_path] if ws_path else None,
                    "headers": ({"Host": ([ws_host] if isinstance(ws_host, str)
                                          else ws_host)}
                                if ws_host else None)})
        else:
            return None
        if node.get("pbk"):
            d["reality-opts"] = _clean({"public-key": node["pbk"],
                                        "short-id": node["sid"] or ""})
    elif ntype == "trojan":
        d["password"] = node["password"]
        if node.get("sni"):
            d["sni"] = node["sni"]
        if node.get("alpn"):
            d["alpn"] = list(node["alpn"])
        if node.get("fp"):
            d["fingerprint"] = node["fp"]
        if node.get("skip_cert_verify") is not None:
            d["skip-cert-verify"] = bool(node["skip_cert_verify"])
        if network == "ws":
            d["network"] = "ws"
            d["ws-opts"] = _clean({"path": ws_path, "headers": (
                {"Host": ws_host} if ws_host else None)})
        elif network == "grpc":
            d["network"] = "grpc"
            d["grpc-opts"] = {"grpc-service-name": service_name or ""}
        elif network in ("tcp", None, ""):
            pass
        else:
            return None
        if node.get("pbk"):
            d["reality-opts"] = _clean({"public-key": node["pbk"],
                                        "short-id": node["sid"] or ""})
    elif ntype == "ss":
        d["cipher"] = ss_cipher
        d["password"] = node["password"]
        if node.get("plugin"):
            d["plugin"] = node["plugin"]
            opts = {}
            for key, val in (node.get("plugin_opts") or {}).items():
                opts[key] = val
            if opts:
                d["plugin-opts"] = opts
    elif ntype == "ssr":
        d["cipher"] = node["cipher"]
        d["password"] = node["password"]
        d["protocol"] = node["ssr_protocol"]
        if node.get("ssr_protocol_param"):
            d["protocol-param"] = node["ssr_protocol_param"]
        d["obfs"] = node["ssr_obfs"]
        if node.get("ssr_obfs_param"):
            d["obfs-param"] = node["ssr_obfs_param"]
    elif ntype == "hysteria2":
        if node.get("mport"):
            return None
        d["password"] = node["password"]
        if node.get("sni"):
            d["sni"] = node["sni"]
        if node.get("alpn"):
            d["alpn"] = list(node["alpn"])
        if node.get("skip_cert_verify") is not None:
            d["skip-cert-verify"] = bool(node["skip_cert_verify"])
        if node.get("hy2_obfs"):
            d["obfs"] = node["hy2_obfs"]
        if node.get("hy2_obfs_password"):
            d["obfs-password"] = node["hy2_obfs_password"]
        if node.get("hy2_up") is not None:
            d["up"] = node["hy2_up"]
        if node.get("hy2_down") is not None:
            d["down"] = node["hy2_down"]
        if node.get("fp"):
            d["fingerprint"] = node["fp"]
    elif ntype == "hysteria":
        d["auth_str"] = node.get("hy1_auth")
        if node.get("hy1_protocol"):
            d["protocol"] = node["hy1_protocol"]
        if node.get("sni"):
            d["sni"] = node["sni"]
        if node.get("alpn"):
            d["alpn"] = list(node["alpn"])
        if node.get("skip_cert_verify") is not None:
            d["skip-cert-verify"] = bool(node["skip_cert_verify"])
        if node.get("hy1_up") is not None:
            d["up"] = node["hy1_up"]
        if node.get("hy1_down") is not None:
            d["down"] = node["hy1_down"]
        if node.get("hy1_obfs"):
            d["obfs"] = node["hy1_obfs"]
        if node.get("fp"):
            d["fingerprint"] = node["fp"]
    elif ntype == "tuic":
        d["uuid"] = node["uuid"]
        d["password"] = node["password"]
        if node.get("sni"):
            d["sni"] = node["sni"]
        if node.get("alpn"):
            d["alpn"] = list(node["alpn"])
        if node.get("tuic_congestion"):
            d["congestion-controller"] = node["tuic_congestion"]
        if node.get("tuic_udp_relay"):
            d["udp-relay-mode"] = node["tuic_udp_relay"]
        if node.get("skip_cert_verify") is not None:
            d["skip-cert-verify"] = bool(node["skip_cert_verify"])
        if node.get("tuic_reduce_rtt") is not None:
            d["reduce-rtt"] = bool(node["tuic_reduce_rtt"])
        if node.get("tuic_max_udp") is not None:
            d["max-udp-relay-packet-size"] = node["tuic_max_udp"]
        if node.get("fp"):
            d["fingerprint"] = node["fp"]
    elif ntype == "socks5":
        if node.get("username"):
            d["username"] = node["username"]
        if node.get("password"):
            d["password"] = node["password"]
        if node.get("tls"):
            d["tls"] = True
            if node.get("sni"):
                d["sni"] = node["sni"]
            if node.get("skip_cert_verify") is not None:
                d["skip-cert-verify"] = bool(node["skip_cert_verify"])
    elif ntype == "http":
        if node.get("username"):
            d["username"] = node["username"]
        if node.get("password"):
            d["password"] = node["password"]
        if node.get("tls"):
            d["tls"] = True
            if node.get("sni"):
                d["sni"] = node["sni"]
            if node.get("skip_cert_verify") is not None:
                d["skip-cert-verify"] = bool(node["skip_cert_verify"])
    return d


MIHOMO_REQUIRED = {
    "vmess": ("uuid",), "vless": ("uuid",), "trojan": ("password",),
    "ss": ("cipher", "password"), "ssr": ("cipher", "password", "protocol", "obfs"),
    "hysteria2": ("password",), "hysteria": ("auth_str",),
    "tuic": ("uuid", "password"), "socks5": (), "http": (),
}


def validate_mihomo(d: dict) -> bool:
    if not isinstance(d, dict):
        return False
    ntype = str(d.get("type", "")).lower()
    if ntype not in MIHOMO_REQUIRED:
        return False
    if not d.get("server") or not parse_port(d.get("port")) or not d.get("name"):
        return False
    for key in MIHOMO_REQUIRED[ntype]:
        if not d.get(key):
            return False
    return True


def source_header_lines(title: str, source_meta, updated: str):
    lines = [f"# {title}",
             "# Generated by Scripts/Free18.py. Do not edit by hand.",
             f"# Generated: {updated}"]
    for item in source_meta:
        if item.get("error"):
            lines.append(f"# - {item['label']}: 0 nodes, updated 未知, sha256 -")
        else:
            lines.append(f"# - {item['label']}: {item['count']} nodes, "
                         f"updated {item['updated'] or '未知'}, "
                         f"sha256 {item['digest'] or '-'}")
    return lines


def render_mihomo(nodes, names, source_meta, updated):
    proxies, skipped = [], Counter()
    for node, name in zip(nodes, names):
        d = to_mihomo_dict(node, name)
        if d is None or not validate_mihomo(d):
            skipped[node["type"]] += 1
            continue
        proxies.append(d)
    if proxies:
        body = "proxies:\n" + "".join(
            "- " + yaml.safe_dump(d, allow_unicode=True, sort_keys=False,
                                  width=1000000,
                                  default_flow_style=True).strip() + "\n"
            for d in proxies)
    else:
        body = "proxies: []\n"
    header = "\n".join(source_header_lines(
        "Free18 - Mihomo / Clash proxy-provider (proxies list)",
        source_meta, updated)) + "\n"
    return header + body, len(proxies), skipped


LOON_SSR_PROTOCOLS = {"origin", "auth_chain_a", "auth_chain_b",
                      "auth_aes128_md5", "auth_aes128_sha1", "auth_sha1_v4",
                      "auth_sha1_v2", "auth_sha1"}
LOON_SSR_OBFS = {"plain", "tls1.2_ticket_auth", "http_simple", "http_post"}
LOON_VMESS_CIPHERS = {"none", "auto", "aes-128-cfb", "aes-128-gcm",
                      "chacha20-ietf-poly1305"}


def _q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _bool_arg(key, value):
    if value is None:
        return None
    return f"{key}={'true' if value else 'false'}"


def to_loon_line(node: dict, name: str):
    ntype = node["type"]
    server, port = node["server"], node["port"]
    network = (node.get("network") or "tcp").lower()
    tls = bool(node.get("tls"))
    args = []
    if ntype == "ss":
        if not node.get("cipher") or node.get("password") is None:
            return None
        head = f"{name} = Shadowsocks,{server},{port},{node['cipher']},{_q(node['password'])}"
        plugin = node.get("plugin") or ""
        opts = node.get("plugin_opts") or {}
        if plugin in ("obfs-local", "simple-obfs", "obfs"):
            if opts.get("obfs") in ("http", "tls"):
                args.append(f"obfs-name={opts['obfs']}")
            elif opts.get("obfs") not in (None, "", "none"):
                return None
            if opts.get("obfs-host"):
                args.append(f"obfs-host={opts['obfs-host']}")
            if opts.get("obfs-uri"):
                args.append(f"obfs-uri={opts['obfs-uri']}")
        elif plugin == "shadow-tls":
            args.append(f"shadow-tls-password={opts.get('password', '')}")
            if opts.get("sni"):
                args.append(f"shadow-tls-sni={opts['sni']}")
            if opts.get("version"):
                args.append(f"shadow-tls-version={opts['version']}")
        elif plugin:
            return None
        return ", ".join([head] + args) if args else head
    if ntype == "ssr":
        if (node.get("ssr_protocol") not in LOON_SSR_PROTOCOLS
                or node.get("ssr_obfs") not in LOON_SSR_OBFS):
            return None
        head = (f"{name} = ShadowsocksR,{server},{port},{node['cipher']},"
                f"{_q(node['password'] or '')},protocol={node['ssr_protocol']}")
        if node.get("ssr_protocol_param"):
            head += f",protocol-param={node['ssr_protocol_param']}"
        head += f",obfs={node['ssr_obfs']}"
        if node.get("ssr_obfs_param"):
            head += f",obfs-param={node['ssr_obfs_param']}"
        return head
    if ntype == "socks5":
        head = f"{name} = socks5,{server},{port}"
        if node.get("username") or node.get("password"):
            head += f",{node.get('username') or ''},{_q(node.get('password') or '')}"
        if tls:
            args.append("over-tls=true")
            if node.get("sni"):
                args.append(f"sni={node['sni']}")
            scv = _bool_arg("skip-cert-verify", node.get("skip_cert_verify"))
            if scv:
                args.append(scv)
        return ", ".join([head] + args) if args else head
    if ntype == "vmess":
        if node.get("cipher") not in LOON_VMESS_CIPHERS:
            return None
        if network not in ("tcp", "ws", "http"):
            return None
        if node.get("alpn"):
            return None
        head = (f"{name} = VMess,{server},{port},{node['cipher']},"
                f"{_q(node['uuid'] or '')},transport={network}")
        args.append(f"alterId={node['alter_id'] if node['alter_id'] is not None else 0}")
        if network in ("ws", "http"):
            if node.get("path"):
                args.append(f"path={node['path']}")
            if node.get("host"):
                args.append(f"host={node['host']}")
        args.append(f"over-tls={'true' if tls else 'false'}")
        if node.get("sni"):
            args.append(f"sni={node['sni']}")
        scv = _bool_arg("skip-cert-verify", node.get("skip_cert_verify"))
        if scv:
            args.append(scv)
        if node.get("pbk"):
            args.append(f"public-key={_q(node['pbk'])}")
        if node.get("sid"):
            args.append(f"short-id={node['sid']}")
        return ", ".join([head] + args)
    if ntype == "vless":
        if network not in ("tcp", "ws", "http"):
            return None
        if node.get("flow") not in (None, "", "xtls-rprx-vision"):
            return None
        head = (f"{name} = VLESS,{server},{port},{_q(node['uuid'] or '')},"
                f"transport={network}")
        if node.get("flow"):
            args.append(f"flow={node['flow']}")
        if network in ("ws", "http"):
            if node.get("path"):
                args.append(f"path={node['path']}")
            if node.get("host"):
                args.append(f"host={node['host']}")
        args.append(f"over-tls={'true' if tls else 'false'}")
        if node.get("sni"):
            args.append(f"sni={node['sni']}")
        scv = _bool_arg("skip-cert-verify", node.get("skip_cert_verify"))
        if scv:
            args.append(scv)
        if node.get("pbk"):
            args.append(f"public-key={_q(node['pbk'])}")
        if node.get("sid"):
            args.append(f"short-id={node['sid']}")
        return ", ".join([head] + args)
    if ntype == "trojan":
        if network not in ("tcp", "ws", "http"):
            return None
        head = (f"{name} = Trojan,{server},{port},{_q(node['password'] or '')},"
                f"transport={'ws' if network in ('ws', 'http') else 'tcp'}")
        if network in ("ws", "http"):
            if node.get("path"):
                args.append(f"path={node['path']}")
            if node.get("host"):
                args.append(f"host={node['host']}")
        if node.get("alpn"):
            args.append(f"alpn={_q(','.join(node['alpn']))}")
        if node.get("sni"):
            args.append(f"sni={node['sni']}")
        scv = _bool_arg("skip-cert-verify", node.get("skip_cert_verify"))
        if scv:
            args.append(scv)
        if node.get("pbk"):
            args.append(f"public-key={_q(node['pbk'])}")
        if node.get("sid"):
            args.append(f"short-id={node['sid']}")
        return ", ".join([head] + args) if args else head
    if ntype == "hysteria2":
        if node.get("hy2_obfs") not in (None, "", "salamander"):
            return None
        head = (f"{name} = Hysteria2,{server},{port},{_q(node['password'] or '')}")
        if node.get("sni"):
            args.append(f"sni={node['sni']}")
        scv = _bool_arg("skip-cert-verify", node.get("skip_cert_verify"))
        if scv:
            args.append(scv)
        if node.get("alpn"):
            args.append(f"alpn={_q(','.join(node['alpn']))}")
        if node.get("hy2_obfs") == "salamander":
            if not node.get("hy2_obfs_password"):
                return None
            args.append(f"salamander-password={node['hy2_obfs_password']}")
        if node.get("mport"):
            match = re.fullmatch(r"(\d+)-(\d+)", node["mport"].strip())
            if not match:
                return None
            args.append(f"server-ports={_q(match.group(1) + ':' + match.group(2))}")
        if node.get("hy2_down") is not None:
            args.append(f"download-bandwidth={node['hy2_down']}")
        return ", ".join([head] + args) if args else head
    return None


def render_loon(nodes, names):
    lines, skipped = [], Counter()
    for node, name in zip(nodes, names):
        line = to_loon_line(node, name)
        if line is None:
            skipped[node["type"]] += 1
        else:
            lines.append(line)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines), skipped


def _qx_bad_value(value) -> bool:
    return value is not None and ("," in str(value) or "\n" in str(value))


def to_qx_line(node: dict, name: str):
    ntype = node["type"]
    server, port = node["server"], node["port"]
    network = (node.get("network") or "tcp").lower()
    tls = bool(node.get("tls"))
    if _qx_bad_value(node.get("password")) or _qx_bad_value(node.get("uuid")):
        return None
    if ntype == "ss":
        if not node.get("cipher") or node.get("password") is None:
            return None
        parts = [f"shadowsocks = {server}:{port}",
                 f"method={node['cipher']}",
                 f"password={node['password']}"]
        plugin = node.get("plugin") or ""
        opts = node.get("plugin_opts") or {}
        if plugin in ("obfs-local", "simple-obfs", "obfs"):
            obfs = opts.get("obfs")
            if obfs == "http":
                parts.append("obfs=http")
            elif obfs == "tls":
                parts.append("obfs=tls")
            elif obfs not in (None, "", "none"):
                return None
            if opts.get("obfs-host"):
                parts.append(f"obfs-host={opts['obfs-host']}")
        elif plugin == "v2ray-plugin":
            mode = str(opts.get("mode", "")).lower()
            use_tls = boolish(opts.get("tls"))
            if mode == "websocket":
                parts.append("obfs=wss" if use_tls else "obfs=ws")
            elif mode in ("", "tcp"):
                if use_tls:
                    parts.append("obfs=over-tls")
            else:
                return None
            if opts.get("path"):
                parts.append(f"obfs-uri={opts['path']}")
            if opts.get("host"):
                parts.append(f"obfs-host={opts['host']}")
        elif plugin == "shadow-tls":
            return None
        elif plugin:
            return None
        parts.append(f"tag={name}")
        return ", ".join(parts)
    if ntype == "ssr":
        parts = [f"shadowsocks = {server}:{port}",
                 f"method={node['cipher']}",
                 f"password={node['password']}",
                 f"ssr-protocol={node['ssr_protocol']}"]
        if node.get("ssr_protocol_param"):
            parts.append(f"ssr-protocol-param={node['ssr_protocol_param']}")
        parts.append(f"obfs={node['ssr_obfs']}")
        if node.get("ssr_obfs_param"):
            parts.append(f"obfs-host={node['ssr_obfs_param']}")
        parts.append(f"tag={name}")
        return ", ".join(parts)
    if ntype == "vmess":
        method_map = {"auto": "chacha20-poly1305", "none": "chacha20-poly1305",
                      "chacha20-poly1305": "chacha20-poly1305",
                      "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
                      "aes-128-gcm": "aes-128-gcm"}
        method = method_map.get((node.get("cipher") or "").lower())
        if method is None or (node.get("alter_id") or 0) != 0:
            return None
        if network in ("grpc", "h2", "kcp", "xhttp", "splithttp"):
            return None
        if node.get("alpn") or node.get("pbk"):
            return None
        parts = [f"vmess = {server}:{port}", f"method={method}",
                 f"password={node['uuid']}", "aead=true"]
        if network == "ws":
            parts.append("obfs=wss" if tls else "obfs=ws")
            if node.get("path"):
                parts.append(f"obfs-uri={node['path']}")
            obfs_host = node.get("host")
            if node.get("sni") and obfs_host and node["sni"] != obfs_host:
                return None
            if obfs_host or node.get("sni"):
                parts.append(f"obfs-host={obfs_host or node['sni']}")
        elif network == "http":
            parts.append("obfs=http")
            if node.get("path"):
                parts.append(f"obfs-uri={node['path']}")
            if node.get("host"):
                parts.append(f"obfs-host={node['host']}")
        elif network == "tcp" and tls:
            parts.append("obfs=over-tls")
        if tls:
            parts.append("tls-verification=false"
                         if node.get("skip_cert_verify") else "tls-verification=true")
        if node.get("sni") and network != "ws":
            parts.append(f"tls-host={node['sni']}")
        parts.append(f"tag={name}")
        return ", ".join(parts)
    if ntype == "trojan":
        if network in ("grpc", "h2", "kcp", "xhttp", "splithttp"):
            return None
        if node.get("pbk"):
            return None
        parts = [f"trojan = {server}:{port}",
                 f"password={node['password']}", "over-tls=true"]
        parts.append("tls-verification=false"
                     if node.get("skip_cert_verify") else "tls-verification=true")
        if node.get("sni"):
            parts.append(f"tls-host={node['sni']}")
        if network == "ws":
            parts.append("obfs=wss")
            if node.get("path"):
                parts.append(f"obfs-uri={node['path']}")
            if node.get("host"):
                parts.append(f"obfs-host={node['host']}")
        parts.append(f"tag={name}")
        return ", ".join(parts)
    if ntype == "http":
        parts = [f"http = {server}:{port}"]
        if node.get("username"):
            parts.append(f"username={node['username']}")
        if node.get("password"):
            parts.append(f"password={node['password']}")
        if tls:
            parts.append("over-tls=true")
        parts.append(f"tag={name}")
        return ", ".join(parts)
    return None


def render_qx(nodes, names):
    lines, skipped = [], Counter()
    for node, name in zip(nodes, names):
        safe_name = name.replace(",", " ").replace("\n", " ").replace("\r", " ").strip()
        line = to_qx_line(node, safe_name)
        if line is None:
            skipped[node["type"]] += 1
        else:
            lines.append(line)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines), skipped


def to_surge_line(node: dict, name: str):
    ntype = node["type"]
    server, port = node["server"], node["port"]
    network = (node.get("network") or "tcp").lower()
    tls = bool(node.get("tls"))
    scv = ("skip-cert-verify=true" if node.get("skip_cert_verify")
           else "skip-cert-verify=false")
    if ntype == "ss":
        if node.get("plugin"):
            return None
        return (f"{name} = ss, {server}, {port}, "
                f"encrypt-method={node['cipher']}, password={node['password']}, "
                f"udp-relay=true")
    if ntype == "vmess":
        if (node.get("alter_id") or 0) != 0 or node.get("pbk"):
            return None
        if network not in ("tcp", "ws", "grpc"):
            return None
        cipher = node.get("cipher") or "auto"
        enc = {"auto": "aes-128-gcm", "aes-128-gcm": "aes-128-gcm",
               "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
               "none": "aes-128-gcm"}.get(cipher.lower())
        if enc is None:
            return None
        parts = [f"{name} = vmess, {server}, {port}",
                 f"username={node['uuid']}", f"encrypt-method={enc}",
                 "vmess-aead=true", f"tls={'true' if tls else 'false'}"]
        if network == "ws":
            parts.append("ws=true")
            if node.get("path"):
                parts.append(f"ws-path={node['path']}")
            if node.get("host"):
                parts.append(f"ws-headers=Host:{node['host']}")
        elif network == "grpc":
            parts.append("grpc=true")
            if node.get("service_name"):
                parts.append(f"grpc-service-name={node['service_name']}")
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("alpn"):
            alpn = ",".join(node["alpn"])
            parts.append(f"alpn={_q(alpn)}" if "," in alpn else f"alpn={alpn}")
        parts.append(scv)
        return ", ".join(parts)
    if ntype == "vless":
        if node.get("pbk"):
            return None
        if network not in ("tcp", "ws", "grpc"):
            return None
        parts = [f"{name} = vless, {server}, {port}",
                 f"uuid={node['uuid']}", f"tls={'true' if tls else 'false'}"]
        if node.get("flow"):
            parts.append(f"flow={node['flow']}")
        if network == "ws":
            parts.append("ws=true")
            if node.get("path"):
                parts.append(f"ws-path={node['path']}")
            if node.get("host"):
                parts.append(f"ws-headers=Host:{node['host']}")
        elif network == "grpc":
            parts.append("grpc=true")
            if node.get("service_name"):
                parts.append(f"grpc-service-name={node['service_name']}")
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("alpn"):
            alpn = ",".join(node["alpn"])
            parts.append(f"alpn={_q(alpn)}" if "," in alpn else f"alpn={alpn}")
        parts.append(scv)
        return ", ".join(parts)
    if ntype == "trojan":
        if node.get("pbk") or network not in ("tcp", "ws"):
            return None
        parts = [f"{name} = trojan, {server}, {port}",
                 f"password={node['password']}"]
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("alpn"):
            alpn = ",".join(node["alpn"])
            parts.append(f"alpn={_q(alpn)}" if "," in alpn else f"alpn={alpn}")
        if network == "ws":
            parts.append("ws=true")
            if node.get("path"):
                parts.append(f"ws-path={node['path']}")
            if node.get("host"):
                parts.append(f"ws-headers=Host:{node['host']}")
        parts.append(scv)
        return ", ".join(parts)
    if ntype == "hysteria2":
        if node.get("mport"):
            return None
        parts = [f"{name} = hysteria2, {server}, {port}",
                 f"password={node['password']}"]
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("alpn"):
            alpn = ",".join(node["alpn"])
            parts.append(f"alpn={_q(alpn)}" if "," in alpn else f"alpn={alpn}")
        if node.get("hy2_obfs"):
            parts.append(f"obfs={node['hy2_obfs']}")
        if node.get("hy2_obfs_password"):
            parts.append(f"obfs-password={node['hy2_obfs_password']}")
        if node.get("hy2_up") is not None:
            parts.append(f"up={node['hy2_up']}")
        if node.get("hy2_down") is not None:
            parts.append(f"down={node['hy2_down']}")
        parts.append(scv)
        return ", ".join(parts)
    if ntype == "tuic":
        if not node.get("uuid") or not node.get("password"):
            return None
        parts = [f"{name} = tuic, {server}, {port}",
                 f"uuid={node['uuid']}", f"password={node['password']}"]
        if node.get("alpn"):
            alpn = ",".join(node["alpn"])
            parts.append(f"alpn={_q(alpn)}" if "," in alpn else f"alpn={alpn}")
        if node.get("tuic_congestion"):
            parts.append(f"congestion-controller={node['tuic_congestion']}")
        if node.get("tuic_udp_relay"):
            parts.append(f"udp-relay-mode={node['tuic_udp_relay']}")
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("tuic_reduce_rtt") is not None:
            parts.append(f"reduce-rtt={'true' if node['tuic_reduce_rtt'] else 'false'}")
        parts.append(scv)
        return ", ".join(parts)
    if ntype == "socks5":
        ptype = "socks5-tls" if tls else "socks5"
        parts = [f"{name} = {ptype}, {server}, {port}"]
        if node.get("username"):
            parts.append(node["username"])
        if node.get("password"):
            parts.append(node["password"])
        if tls:
            if node.get("sni"):
                parts.append(f"sni={node['sni']}")
            parts.append(scv)
        return ", ".join(parts)
    if ntype == "http":
        ptype = "https" if tls else "http"
        parts = [f"{name} = {ptype}, {server}, {port}"]
        if node.get("username"):
            parts.append(node["username"])
        if node.get("password"):
            parts.append(node["password"])
        if tls and node.get("sni"):
            parts.append(f"sni={node['sni']}")
        return ", ".join(parts)
    return None


def render_surge(nodes, names, source_meta, updated):
    lines, skipped = [], Counter()
    for node, name in zip(nodes, names):
        line = to_surge_line(node, name)
        if line is None:
            skipped[node["type"]] += 1
        else:
            lines.append(line)
    header = "\n".join(source_header_lines(
        "Free18 - Surge [Proxy] section (node subscription)",
        source_meta, updated)) + "\n\n[Proxy]\n"
    body = "\n".join(lines)
    return header + body + ("\n" if lines else ""), len(lines), skipped


def _hostport(node: dict) -> str:
    server = node["server"]
    if ":" in server and not server.startswith("["):
        server = f"[{server}]"
    return f"{server}:{node['port']}"


def _query_str(query: dict) -> str:
    if not query:
        return ""
    return urlencode(query, doseq=True, quote_via=quote)


def _rebuild_query_link(scheme: str, userinfo: str, node: dict, name: str) -> str:
    query = dict(node.get("query") or {})
    link = f"{scheme}{userinfo}@{_hostport(node)}"
    qs = _query_str(query)
    if qs:
        link += "?" + qs
    return link + "#" + quote(name, safe="")


def _build_query(node: dict) -> dict:
    query = {}
    if node.get("flow"):
        query["flow"] = node["flow"]
    if node.get("encryption"):
        query["encryption"] = node["encryption"]
    if node.get("security"):
        query["security"] = node["security"]
    if node.get("sni"):
        query["sni"] = node["sni"]
    if node.get("fp"):
        query["fp"] = node["fp"]
    if node.get("pbk"):
        query["pbk"] = node["pbk"]
    if node.get("sid"):
        query["sid"] = node["sid"]
    if node.get("network"):
        query["type"] = node["network"]
    if node.get("path"):
        query["path"] = node["path"]
    if node.get("host"):
        query["host"] = node["host"]
    if node.get("header_type"):
        query["headerType"] = node["header_type"]
    if node.get("service_name"):
        query["serviceName"] = node["service_name"]
    if node.get("alpn"):
        query["alpn"] = ",".join(node["alpn"])
    if node.get("packet_encoding"):
        query["packetEncoding"] = node["packet_encoding"]
    return query


def to_shadowrocket_link(node: dict, name: str):
    ntype = node["type"]
    if ntype == "vmess":
        data = {
            "v": "2", "ps": name, "add": node["server"],
            "port": str(node["port"]), "id": node["uuid"],
            "aid": str(node["alter_id"] if node["alter_id"] is not None else 0),
            "scy": node["cipher"] or "auto",
            "net": node["network"] or "tcp",
            "type": node["header_type"] or "none",
            "host": node["host"] or "",
            "path": node["path"] or "",
            "tls": "tls" if node.get("tls") else "",
            "sni": node.get("sni") or "",
            "alpn": ",".join(node["alpn"]) if node.get("alpn") else "",
            "fp": node.get("fp") or "",
        }
        for key, val in (node.get("vmess_json") or {}).items():
            data.setdefault(key, val)
        payload = json.dumps(data, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
        return "vmess://" + b64encode_std(payload)
    if ntype == "vless":
        query = dict(node.get("query") or {}) or _build_query(node)
        return _rebuild_query_link("vless://", quote(node["uuid"] or "", safe=""),
                                   {**node, "query": query}, name)
    if ntype == "trojan":
        query = dict(node.get("query") or {}) or _build_query(node)
        return _rebuild_query_link("trojan://", quote(node["password"] or "", safe=""),
                                   {**node, "query": query}, name)
    if ntype == "ss":
        userinfo = b64encode_url_nopad(
            f"{node['cipher']}:{node['password']}".encode("utf-8"))
        link = f"ss://{userinfo}@{_hostport(node)}"
        query = dict(node.get("ss_query") or {})
        if node.get("plugin"):
            plugin = node["plugin"]
            opts = node.get("plugin_opts") or {}
            pieces = []
            for key, val in opts.items():
                pieces.append(f"{key}={val}" if val is not True else key)
            if pieces:
                plugin += ";" + ";".join(pieces)
            query["plugin"] = plugin
        qs = _query_str(query)
        if qs:
            link += "?" + qs
        return link + "#" + quote(name, safe="")
    if ntype == "ssr":
        params = dict(node.get("ssr_params") or {})
        if node.get("ssr_obfs_param"):
            params["obfsparam"] = b64encode_url_nopad(
                node["ssr_obfs_param"].encode("utf-8"))
        if node.get("ssr_protocol_param"):
            params["protoparam"] = b64encode_url_nopad(
                node["ssr_protocol_param"].encode("utf-8"))
        params["remarks"] = b64encode_url_nopad(name.encode("utf-8"))
        body = (f"{node['server']}:{node['port']}:{node['ssr_protocol']}:"
                f"{node['cipher']}:{node['ssr_obfs']}:"
                f"{b64encode_url_nopad((node['password'] or '').encode('utf-8'))}"
                f"/?{_query_str(params)}")
        return "ssr://" + b64encode_url_nopad(body.encode("utf-8"))
    if ntype == "hysteria2":
        query = dict(node.get("query") or {}) or _build_query(node)
        if node.get("sni") and "sni" not in query:
            query["sni"] = node["sni"]
        if node.get("hy2_obfs"):
            query.setdefault("obfs", node["hy2_obfs"])
        if node.get("hy2_obfs_password"):
            query.setdefault("obfs-password", node["hy2_obfs_password"])
        if node.get("mport"):
            query.setdefault("mport", node["mport"])
        return _rebuild_query_link(
            "hysteria2://", quote(node["password"] or "", safe=""),
            {**node, "query": query}, name)
    if ntype == "tuic":
        query = dict(node.get("query") or {}) or _build_query(node)
        userinfo = (quote(node["uuid"] or "", safe="") + ":"
                    + quote(node["password"] or "", safe=""))
        return _rebuild_query_link("tuic://", userinfo, {**node, "query": query}, name)
    return None


def render_shadowrocket(nodes, names):
    links, skipped = [], Counter()
    for node, name in zip(nodes, names):
        link = to_shadowrocket_link(node, name)
        if link is None:
            skipped[node["type"]] += 1
        else:
            links.append(link)
    blob = b64encode_std(("\n".join(links) + "\n").encode("utf-8"))
    return blob + "\n", len(links), skipped


def _sup_num(n: int) -> str:
    digits = "⁰¹²³⁴⁵⁶⁷⁸⁹"
    return "".join(digits[int(ch)] for ch in str(n))


def lookup_geo(ips, session, sleep_fn=time.sleep):
    now = datetime.now(timezone.utc)
    result = {}
    todo = list(dict.fromkeys(ips))
    for start in range(0, len(todo), 100):
        if (start // 100) % 10 == 0:
            print(f"[Free18] 地理查询：{start}/{len(todo)} 个 IP", flush=True)
        batch = todo[start:start + 100]
        payload = [{"query": ip} for ip in batch]
        data = None
        for attempt in range(4):
            try:
                resp = session.post(
                    "http://ip-api.com/batch?lang=zh-CN&fields=status,message,"
                    "country,countryCode,regionName,city,query",
                    json=payload, timeout=30)
            except requests.RequestException:
                resp = None
            if resp is not None and resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    data = None
                break
            if resp is not None and resp.status_code in (429, 500, 502, 503, 504):
                wait = 10 * (attempt + 1)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = min(120, max(wait, int(retry_after)))
                    except ValueError:
                        pass
                sleep_fn(wait)
                continue
            break
        if not isinstance(data, list):
            for ip in batch:
                result[ip] = None
            continue
        for item in data:
            ip = item.get("query")
            if not ip:
                continue
            if item.get("status") == "success" and item.get("countryCode"):
                entry = {
                    "ok": True,
                    "countryCode": item["countryCode"],
                    "country": item.get("country") or "",
                    "region": item.get("regionName") or "",
                    "city": item.get("city") or "",
                    "updated": now.isoformat(),
                }
                result[ip] = entry
            else:
                result[ip] = None
        if start + 100 < len(todo):
            sleep_fn(1.0)
    return result


def display_name(node: dict, geo):
    server = norm_server(node["server"])
    orig = (node.get("name_orig") or "").strip()
    fallback = orig or f"{node['type']} {server}:{node['port']}"
    if not is_ip(server) or not geo:
        return fallback
    code = (geo.get("countryCode") or "").upper()
    country = COUNTRY_ZH.get(code) or (geo.get("country") or "").strip()
    if not code or not country:
        return fallback
    city = (geo.get("city") or geo.get("region") or "").strip()
    flag = flag_emoji(code)
    if city:
        return f"{flag} {country} {city}  {server}"
    return f"{flag} {country}  {server}"


def assign_names(nodes, geo_map):
    bases = []
    for node in nodes:
        geo = geo_map.get(norm_server(node["server"]))
        node["_geo"] = geo
        bases.append(display_name(node, geo))
    groups = {}
    for idx, base in enumerate(bases):
        groups.setdefault(base, []).append(idx)
    names = list(bases)
    for base, idxs in groups.items():
        if len(idxs) >= 2:
            for pos, idx in enumerate(idxs, start=1):
                names[idx] = base + _sup_num(pos)
    order = sorted(
        range(len(nodes)),
        key=lambda i: (
            (nodes[i]["_geo"] or {}).get("countryCode") or "",
            (nodes[i]["_geo"] or {}).get("city")
            or (nodes[i]["_geo"] or {}).get("region") or "",
            norm_server(nodes[i]["server"]),
            nodes[i]["port"] or 0,
            nodes[i]["type"],
        ),
    )
    return [nodes[i] for i in order], [names[i] for i in order]


def render_readme(stats: dict, fingerprints: dict, counts: dict, updated: str) -> str:
    lines = [
        '# <img src="https://raw.githubusercontent.com/alienwaregf/personal-use/refs/heads/main/Picture/icon/OpenClash.png" width="25" height="25" alt="Clash" /> Clash',
        "",
        "Free18",
        "```text",
        RAW_BASE + "Free18.yaml",
        "```",
        "",
        "VPNgate",
        "```text",
        RAW_BASE + "VPNgate.yaml",
        "```",
        "",
        '# <img src="https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/02ProxySoftLogo/Loon(1).png" width="25" height="25" alt="Loon" /> Loon',
        "",
        "```text",
        RAW_BASE + "Free18_Loon.list",
        "```",
        "",
        '# <img src="https://raw.githubusercontent.com/alienwaregf/personal-use/refs/heads/main/Picture/icon/QX.png" width="25" height="25" alt="QuantumultX" /> QuantumultX',
        "",
        "```text",
        RAW_BASE + "Free18_QuantumultX.list",
        "```",
        "",
        '# <img src="https://raw.githubusercontent.com/alienwaregf/personal-use/refs/heads/main/Picture/icon/shadowrocket.png" width="25" height="25" alt="Shadowrocket" /> Shadowrocket',
        "",
        "```text",
        RAW_BASE + "Free18_Shadowrocket.list",
        "```",
        "",
        '# <img src="https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/02ProxySoftLogo/Surge(8).png" width="25" height="25" alt="Surge" /> Surge',
        "",
        "```text",
        RAW_BASE + "Free18_Surge.list",
        "```",
    ]
    return "\n".join(lines) + "\n"


def fetch_url(session, url: str, timeout: int = 30):
    last_error = None
    for attempt in range(4):
        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException as exc:
            last_error = str(exc)
            time.sleep(2 * (attempt + 1))
            continue
        if resp.status_code == 200:
            if len(resp.content) > 30 * 1024 * 1024:
                raise RuntimeError("response too large (>30MB)")
            return resp.text
        last_error = f"HTTP {resp.status_code}"
        if resp.status_code in (429, 500, 502, 503, 504) and attempt < 3:
            wait = 2 * (attempt + 1)
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = min(60, max(wait, int(retry_after)))
                except ValueError:
                    pass
            time.sleep(wait)
            continue
        raise RuntimeError(last_error)
    raise RuntimeError(last_error or "fetch failed")


DISCOVERY = {
    "ripaojiedian": ("https://api.github.com/repos/ripaojiedian/freenode/contents/",
                     "contents", [r"^clash$", r"^sub$"]),
    "shaoyouvip": ("https://api.github.com/repos/shaoyouvip/free/contents/",
                   "contents", [r"^mihomo\.yaml$", r"^all\.yaml$"]),
    "lagzian": ("https://api.github.com/repos/lagzian/SS-Collector/contents/configs",
                "contents", [r"^subscription-all\.b64$"]),
    "clashfree": ("https://api.github.com/repos/free-nodes/clashfree/contents/",
                  "contents", [r"^sub\.yml$", r"^clash\d{8}\.ya?ml$"]),
    "jsnzkpg": ("https://api.github.com/repos/Jsnzkpg/Jsnzkpg/contents/",
                "contents", [r"^Jsnzkpg$"]),
    "psg-mix": ("https://api.github.com/repos/itsyebekhe/PSG/contents/subscriptions/xray",
                "contents", [r"^mix$"]),
    "chromego": ("https://api.github.com/repos/Misaka-blog/chromego_merge/contents/sub",
                 "contents", [r"^merged_proxies_new\.yaml$", r"^merged.*\.yaml$"]),
    "free18": ("https://api.github.com/repos/free18/v2ray/contents/",
               "contents", [r"^v\.txt$", r"^c\.yaml$"]),
    "nomorewalls": ("https://api.github.com/repos/peasoft/NoMoreWalls/contents/",
                    "contents", [r"^list\.txt$", r"^list\.ya?ml$"]),
    "mahdibland": ("https://api.github.com/repos/mahdibland/V2RayAggregator/contents/",
                   "contents", [r"^Eternity$", r"^Eternity\.txt$"]),
    "dafeide": ("https://api.github.com/gists/7a072d3de39083d469988844ba2ef165",
                "gist", [r"^v2ray$", r"^clash\.yaml$"]),
}


def branch_swap_url(url: str):
    parts = urlsplit(url)
    segs = parts.path.strip("/").split("/")
    if len(segs) >= 4 and segs[2] in ("main", "master"):
        segs[2] = "master" if segs[2] == "main" else "main"
        return parts._replace(path="/" + "/".join(segs)).geturl()
    return None


def discover_candidates(session, key: str):
    spec = DISCOVERY.get(key)
    if not spec:
        return []
    api_url, kind, patterns = spec
    resp = session.get(api_url, timeout=30,
                       headers={"Accept": "application/vnd.github+json"})
    if resp.status_code != 200:
        raise RuntimeError(f"发现接口 HTTP {resp.status_code}")
    data = resp.json()
    if kind == "gist":
        entries = [(name, info.get("raw_url"))
                   for name, info in (data.get("files") or {}).items()]
    else:
        entries = [(e.get("name", ""), e.get("download_url"))
                   for e in data if isinstance(e, dict)]
    by_name = dict(entries)
    candidates = []
    for pattern in patterns:
        matched = sorted((name for name, _u in entries
                          if _u and re.match(pattern, name)), reverse=True)
        for name in matched:
            if by_name[name] not in candidates:
                candidates.append(by_name[name])
    return candidates


def lookup_upstream_updated(session, url: str) -> str:
    try:
        parts = urlsplit(url)
        segs = parts.path.strip("/").split("/")
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN") or ""
        if token:
            headers["Authorization"] = "Bearer " + token
        if parts.netloc == "raw.githubusercontent.com" and len(segs) >= 4:
            api = ("https://api.github.com/repos/" + segs[0] + "/" + segs[1]
                   + "/commits?path=" + quote("/".join(segs[3:]), safe="/")
                   + "&sha=" + segs[2] + "&per_page=1")
            resp = session.get(api, timeout=15, headers=headers)
            if resp.status_code != 200:
                return ""
            data = resp.json()
            if not isinstance(data, list) or not data:
                return ""
            commit = data[0].get("commit") or {}
            date = ((commit.get("committer") or {}).get("date")
                    or (commit.get("author") or {}).get("date") or "")
            return str(date)
        if parts.netloc == "gist.githubusercontent.com" and len(segs) >= 2:
            resp = session.get("https://api.github.com/gists/" + segs[1],
                               timeout=15, headers=headers)
            if resp.status_code != 200:
                return ""
            return str(resp.json().get("updated_at") or "")
    except Exception:
        return ""
    return ""


def fetch_source(session, key: str, label: str, url: str):

    errors = []
    actual = url
    try:
        text = fetch_url(session, url)
    except RuntimeError as exc:
        errors.append(str(exc))
        if not str(exc).startswith(("HTTP 404", "HTTP 410")):
            raise
        text = None
    if text is None:
        swapped = branch_swap_url(url)
        if swapped:
            try:
                text = fetch_url(session, swapped)
                actual = swapped
                print(f"[Free18] {label}：主地址 404，已用分支回退：{swapped}", flush=True)
            except RuntimeError as exc:
                errors.append(str(exc))
        if text is None:
            try:
                candidates = discover_candidates(session, key)
            except Exception as exc:
                errors.append(f"发现：{exc}")
                candidates = []
            for cand in candidates:
                if cand in (url, swapped):
                    continue
                try:
                    text = fetch_url(session, cand)
                    actual = cand
                    print(f"[Free18] {label}：已改名或移动，已发现：{cand}", flush=True)
                    break
                except RuntimeError as exc:
                    errors.append(str(exc))
    if text is None:
        raise RuntimeError("; ".join(errors) or "抓取失败")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    updated = lookup_upstream_updated(session, actual)
    return text, actual, updated, digest


def write_if_changed(path: Path, text: str) -> bool:
    data = text.encode("utf-8")
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return True


def run_pipeline(root: Path, sources, fetch_fn, geo_fn, now: datetime):
    root = Path(root)
    proxy_dir = root / "proxy"
    scripts_dir = root / "Scripts"

    per_source = {}
    failed_sources = []
    source_meta = []
    all_nodes = []
    for key, label, url in sources:
        try:
            fetched = fetch_fn(key, label, url)
        except Exception as exc:
            failed_sources.append({"key": key, "label": label, "error": str(exc)})
            per_source[key] = 0
            source_meta.append({"key": key, "label": label, "count": 0,
                                "updated": "", "digest": "", "error": str(exc)})
            print(f"[Free18] 来源失败：{label}：{exc}", flush=True)
            continue
        if isinstance(fetched, tuple):
            text, _actual, meta_updated, digest = fetched
        else:
            text = fetched
            meta_updated = ""
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        try:
            nodes, kind = parse_content(text)
        except Exception as exc:
            failed_sources.append({"key": key, "label": label,
                                   "error": f"解析错误：{exc}"})
            per_source[key] = 0
            source_meta.append({"key": key, "label": label, "count": 0,
                                "updated": meta_updated, "digest": digest,
                                "error": f"解析错误：{exc}"})
            continue
        if not nodes:
            failed_sources.append({"key": key, "label": label,
                                   "error": "解析出 0 个节点"})
            per_source[key] = 0
            source_meta.append({"key": key, "label": label, "count": 0,
                                "updated": meta_updated, "digest": digest,
                                "error": "解析出 0 个节点"})
            continue
        per_source[key] = len(nodes)
        source_meta.append({"key": key, "label": label, "count": len(nodes),
                            "updated": meta_updated, "digest": digest,
                            "error": ""})
        for node in nodes:
            node["_source"] = key
        all_nodes.extend(nodes)
        print(f"[Free18] {label}：{len(nodes)} 个节点", flush=True)

    if not all_nodes:
        stats = {"updated": now.strftime("%Y-%m-%d %H:%M UTC"), "total": 0,
                 "duplicates": 0, "per_source": per_source,
                 "failed_sources": failed_sources, "per_file": {},
                 "geo_failed": [], "gfw_excluded": 0,
                 "cf_excluded": 0, "no_geo_excluded": 0, "changed": False,
                 "country_cap_removed": 0, "per_country": {},
                 "sources": source_meta}
        (scripts_dir / STATS_NAME).write_text(
            json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print("[Free18] 全部来源失败，未写入任何内容", flush=True)
        return stats, 1

    nodes, duplicates = dedupe(all_nodes)
    cf_excluded = 0
    kept = []
    for node in nodes:
        if is_cloudflare_ip(node["server"]) and (node.get("host") or node.get("sni")):
            cf_excluded += 1
        else:
            kept.append(node)
    nodes = kept
    ip_servers = sorted({norm_server(n["server"]) for n in nodes
                         if is_ip(norm_server(n["server"]))})
    geo_map = geo_fn(ip_servers) if geo_fn else {}
    geo_failed = sorted(ip for ip in ip_servers if not geo_map.get(ip))
    gfw_excluded = 0
    kept = []
    for node in nodes:
        geo = geo_map.get(norm_server(node["server"]))
        if geo and (geo.get("countryCode") or "").upper() in GFW_COUNTRIES:
            gfw_excluded += 1
        else:
            kept.append(node)
    nodes = kept
    no_geo_excluded = 0
    kept = []
    for node in nodes:
        geo = geo_map.get(norm_server(node["server"]))
        if geo:
            code = (geo.get("countryCode") or "").upper()
            country = COUNTRY_ZH.get(code) or (geo.get("country") or "").strip()
        else:
            code = ""
            country = ""
        if is_ip(norm_server(node["server"])) and code and country:
            kept.append(node)
        else:
            no_geo_excluded += 1
    nodes = kept
    groups = {}
    for node in nodes:
        geo = geo_map.get(norm_server(node["server"])) or {}
        code = (geo.get("countryCode") or "").upper()
        groups.setdefault(code, []).append(node)
    per_country = {}
    cap_removed = 0
    kept = []
    for code, group in groups.items():
        before = len(group)
        if code not in COUNTRY_CAP_EXEMPT and before > COUNTRY_CAP:
            rng = random.Random(COUNTRY_CAP_SEED + ":" + code)
            group = rng.sample(group, COUNTRY_CAP)
            cap_removed += before - COUNTRY_CAP
        per_country[code] = len(group)
        kept.extend(group)
    per_country = dict(sorted(per_country.items()))
    nodes = kept
    nodes, names = assign_names(nodes, geo_map)
    updated = now.strftime("%Y-%m-%d %H:%M UTC")

    rendered = {}
    counts = {}
    skipped_all = {}
    rendered["Free18.yaml"], counts["Free18.yaml"], skipped_all["Free18.yaml"] = \
        render_mihomo(nodes, names, source_meta, updated)
    rendered["Free18_Loon.list"], counts["Free18_Loon.list"], skipped_all["Free18_Loon.list"] = \
        render_loon(nodes, names)
    rendered["Free18_QuantumultX.list"], counts["Free18_QuantumultX.list"], skipped_all["Free18_QuantumultX.list"] = \
        render_qx(nodes, names)
    rendered["Free18_Shadowrocket.list"], counts["Free18_Shadowrocket.list"], skipped_all["Free18_Shadowrocket.list"] = \
        render_shadowrocket(nodes, names)
    rendered["Free18_Surge.list"], counts["Free18_Surge.list"], skipped_all["Free18_Surge.list"] = \
        render_surge(nodes, names, source_meta, updated)

    fingerprints = {fname: hashlib.sha256(text.encode("utf-8")).hexdigest()
                    for fname, text in rendered.items()}
    stats = {"updated": updated, "total": len(nodes), "duplicates": duplicates,
             "per_source": per_source, "failed_sources": failed_sources,
             "per_file": {fname: {"nodes": counts[fname],
                                  "skipped": dict(skipped_all[fname]),
                                  "sha256": fingerprints[fname]}
                        for fname in rendered},
             "geo_failed": geo_failed, "gfw_excluded": gfw_excluded,
             "cf_excluded": cf_excluded, "no_geo_excluded": no_geo_excluded, "changed": False,
             "country_cap_removed": cap_removed, "per_country": per_country,
             "sources": source_meta}

    changed = False
    for fname, text in rendered.items():
        if write_if_changed(proxy_dir / fname, text):
            changed = True
    readme = render_readme(stats, fingerprints, counts, updated)
    if write_if_changed(proxy_dir / "README.md", readme):
        changed = True
    stats["changed"] = changed
    (scripts_dir / STATS_NAME).write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for fname in rendered:
        print(f"[Free18] {fname}：{counts[fname]} 个节点，"
              f"已跳过={dict(skipped_all[fname])}", flush=True)
    print(f"[Free18] 总计={len(nodes)} 去重={duplicates} "
          f"排除={gfw_excluded} CF排除={cf_excluded} 无归属={no_geo_excluded} 国家上限删={cap_removed} 失败来源={len(failed_sources)} "
          f"地理失败={len(geo_failed)} 已变更={changed}", flush=True)
    return stats, 0


def main(argv=None) -> int:
    root = Path(__file__).resolve().parent.parent
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    now = datetime.now(timezone.utc)

    def fetch_fn(key, label, url):
        return fetch_source(session, key, label, url)

    def geo_fn(ips):
        return lookup_geo(ips, session)

    try:
        _stats, code = run_pipeline(root, SOURCES, fetch_fn, geo_fn, now)
    except Exception as exc:
        print(f"[Free18] 致命错误：{exc}", file=sys.stderr, flush=True)
        return 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
