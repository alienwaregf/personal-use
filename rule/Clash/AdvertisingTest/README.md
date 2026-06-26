> [!TIP]
> 本目录下的规则已由上游格式自动转换为 Mihomo Binary MRS 格式。

# 🧸 去广告测试版

## 前言

![](https://shields.io/badge/-移除重复规则-ff69b4) ![](https://shields.io/badge/-移除无法解析的域名-important) ![](https://shields.io/badge/-DOMAIN与DOMAIN--SUFFIX合并-green) ![](https://shields.io/badge/-DOMAIN--SUFFIX间合并-critical) ![](https://shields.io/badge/-DOMAIN与DOMAIN--KEYWORD合并-9cf) ![](https://shields.io/badge/-DOMAIN--SUFFIX与DOMAIN--KEYWORD合并-blue) ![](https://shields.io/badge/-IP--CIDR(6)合并-blueviolet) ![](https://shields.io/badge/-MITM--HOSTNAME合并-brightgreen) 

去广告测试版规则由《RULE GENERATOR 规则生成器》自动生成。

分流规则是互联网公共服务的域名和IP地址汇总，所有数据均收集自互联网公开信息，不代表我们支持或使用这些服务。

请通过【中华人民共和国 People's Republic of China】合法的互联网出入口信道访问规则中的地址，并确保在使用过程中符合相关法律法规。

## 规则说明
测试版的去广告规则。

会将所有已知的去广告规则作为数据源，不考虑APP承受能力，不考虑误拦截的问题。

也无法处理任何关于误拦截的反馈。

如无必要，非常不建议使用，可能会有严重的副作用。

## 规则统计

最后更新时间：2026-06-26 02:46:59

各类型规则统计：
| 类型 | 数量(条)  | 
| ---- | ----  |
| DOMAIN | 13170  | 
| DOMAIN-KEYWORD | 280  | 
| DOMAIN-SUFFIX | 269536  | 
| IP-CIDR | 508  | 
| IP-CIDR6 | 3  | 
| TOTAL | 283497  |

## Clash

**Domain 规则 (必须同时使用):**

```text
https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/AdvertisingTest/AdvertisingTest_Domain.mrs
```

**IP 规则 (必须同时使用):**

```text
https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/AdvertisingTest/AdvertisingTest_IP.mrs
```

**Classical 规则 (单独使用):**

```text
https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/AdvertisingTest/AdvertisingTest_Classical.mrs
```
