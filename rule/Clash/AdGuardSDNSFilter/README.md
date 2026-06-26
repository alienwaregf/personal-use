# 🧸 AdGuardSDNSFilter

## 前言

![](https://shields.io/badge/-移除重复规则-ff69b4) ![](https://shields.io/badge/-DOMAIN与DOMAIN--SUFFIX合并-green) ![](https://shields.io/badge/-DOMAIN--SUFFIX间合并-critical) ![](https://shields.io/badge/-DOMAIN与DOMAIN--KEYWORD合并-9cf) ![](https://shields.io/badge/-DOMAIN--SUFFIX与DOMAIN--KEYWORD合并-blue) 

AdGuardSDNSFilter规则由《RULE GENERATOR 规则生成器》自动生成。

分流规则是互联网公共服务的域名和IP地址汇总，所有数据均收集自互联网公开信息，不代表我们支持或使用这些服务。

请通过【中华人民共和国 People's Republic of China】合法的互联网出入口信道访问规则中的地址，并确保在使用过程中符合相关法律法规。

## 规则说明
AdGuard DNS Filter 规则！！

建议搭配子目录下的Direct进行放行！！

实验性规则！！谨慎评估后使用！！

如有异常请反馈！！

## 规则统计

最后更新时间：2025-06-06 09:18:35

各类型规则统计：
| 类型 | 数量(条)  | 
| ---- | ----  |
| DOMAIN | 62  | 
| DOMAIN-SUFFIX | 108988  | 
| TOTAL | 109050  | 


## Clash 


Domain 规则（必须同时使用）
```text
https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.mrs
```

IP 规则（必须同时使用）
```text
https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_IP.mrs
```

Classical 规则（单独使用）
```text
https://raw.githubusercontent.com/alienwaregf/personal-use/main/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml
```

#### 配置建议
- AdGuardSDNSFilter_Domain.yaml 单独使用。
- AdGuardSDNSFilter_Classical.yaml 单独使用。
- AdGuardSDNSFilter.yaml、AdGuardSDNSFilter_Domain.yaml 共同使用。

#### 规则链接
**MASTER分支 (每日更新)**

https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter.yaml

https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml

https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.txt

**MASTER分支 CDN (每日更新)**

https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter.yaml

https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml

https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.txt

**MASTER分支 GHProxy (每日更新)**

https://ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter.yaml

https://ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml

https://ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.txt

**RELEASE分支 (不定时更新)**

https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter.yaml

https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml

https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.txt

**RELEASE分支CDN (不定时更新)**

https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter.yaml

https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml

https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.txt

**RELEASE分支 GHProxy (不定时更新)**

https://ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter.yaml

https://ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Classical.yaml

https://ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/release/rule/Clash/AdGuardSDNSFilter/AdGuardSDNSFilter_Domain.txt

## 子规则/排除规则


当前分流规则，未包含其他子规则。

## 数据来源

《AdGuardSDNSFilter》的数据来自以下链接，如与本项目的《AdGuardSDNSFilter》规则混合使用，可能会造成规则大量重复。

- https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt


感谢以上规则作者的辛勤付出（排名不分先后）。

## 最后

### 感谢

[@fiiir](https://github.com/fiiir) [@Tartarus2014](https://github.com/Tartarus2014) [@zjcfynn](https://github.com/zjcfynn) [@chenyiping1995](https://github.com/chenyiping1995) [@vhdj](https://github.com/vhdj)

提供规则数据源及改进建议。

### 其他

请不要对外宣传本项目。