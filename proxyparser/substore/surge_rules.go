package substore

import (
	"fmt"
	"strings"
)

// Clash 规则 → Surge 规则。
//
// 原则与 Loon 那份(loon_config.go)一致:关键字要么翻译、要么丢弃,绝不原样透传。
// Surge 读到不认识的规则行会**整份配置**拒载(surge-cli --check 报「第 N 行存在无效配置」,
// 一键导入直接失败),比 Loon 的「这一行失效」更严重。
//
// 名单依据 Surge 官方规则总览 https://manual.nssurge.com/rules/overview.html ,
// 并用 surge-cli --check(Surge Mac 6.10)逐个核对过:
//
//	DST-PORT     Surge 拼作 DEST-PORT      → 改名
//	SRC-IP-CIDR  Surge 叫 SRC-IP            → 改名
//	NETWORK      Surge 叫 PROTOCOL,值大写  → 改名
//	GEOSITE      Surge 没有                 → 展开成域名规则,展不开就丢弃
//	DOMAIN-REGEX Surge 没有                 → 丢弃
var surgeRuleKeywordAlias = map[string]string{
	"DOMAIN": "DOMAIN", "DOMAIN-SUFFIX": "DOMAIN-SUFFIX", "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
	"DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
	"IP-CIDR":         "IP-CIDR", "IP-CIDR6": "IP-CIDR6", "IP6-CIDR": "IP-CIDR6",
	"GEOIP": "GEOIP", "IP-ASN": "IP-ASN",
	"USER-AGENT": "USER-AGENT", "URL-REGEX": "URL-REGEX",
	"PROCESS-NAME": "PROCESS-NAME",
	"DST-PORT":     "DEST-PORT", "DEST-PORT": "DEST-PORT", "SRC-PORT": "SRC-PORT", "IN-PORT": "IN-PORT",
	"SRC-IP-CIDR": "SRC-IP", "SRC-IP": "SRC-IP",
	"NETWORK": "PROTOCOL", "PROTOCOL": "PROTOCOL",
	"AND": "AND", "OR": "OR", "NOT": "NOT",
	"RULE-SET": "RULE-SET",
	"FINAL":    "FINAL",
}

var surgeIPRuleKeywords = map[string]bool{
	"IP-CIDR": true, "IP-CIDR6": true, "GEOIP": true, "IP-ASN": true,
}

// ConvertClashRulesToSurgeFormat 把 clash 规则转成 Surge [Rule] 行。
//
// RULE-SET 与 GEOSITE 先交给注入的规则集解析器(与 Loon 共用,主控实现:SSRF 安全抓取 + 缓存)
// 展开成规则内联 —— Surge 读不懂 clash 的 YAML / MRS 规则集,GEOSITE 更是根本没有。
// 解析不了时:RULE-SET 退回远程地址(.yaml 猜同目录 .list,.mrs 丢弃),GEOSITE 丢弃。
// 丢掉的规则以 `# 已忽略(原因):原规则` 注释留在原位,Surge 忽略 # 行。
func ConvertClashRulesToSurgeFormat(rules []string, ruleProviders map[string]ClashRuleProvider) ([]string, error) {
	var out []string
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		parts := splitRuleTopLevel(rule)
		if len(parts) < 2 {
			continue
		}
		kw := strings.ToUpper(strings.TrimSpace(parts[0]))

		switch kw {
		case "MATCH", "FINAL":
			out = append(out, "FINAL,"+strings.TrimSpace(parts[1]))

		case "GEOSITE":
			if len(parts) < 3 {
				out = append(out, surgeDropNote(rule, "GEOSITE 缺少策略"))
				continue
			}
			name := strings.ToLower(strings.TrimSpace(parts[1]))
			policy := strings.TrimSpace(parts[2])
			if name == "" || policy == "" {
				out = append(out, surgeDropNote(rule, "GEOSITE 类目名或策略为空"))
				continue
			}
			if resolved, ok := resolveLoonRuleSet("geosite:"+name, ClashRuleProvider{
				Type: "http", Behavior: "domain", Format: "text", URL: geositeDomainListURL(name),
			}, policy); ok {
				if kept, dropped := keepSurgeReadableRules(resolved); len(kept) > 0 {
					out = append(out, kept...)
					if dropped > 0 {
						out = append(out, fmt.Sprintf("# GEOSITE,%s 展开时跳过 %d 条 Surge 不支持的规则", name, dropped))
					}
					continue
				}
			}
			out = append(out, surgeDropNote(rule, "Surge 没有 GEOSITE,类目内容拿不到或太大"))

		case "RULE-SET":
			if len(parts) < 3 {
				out = append(out, surgeDropNote(rule, "RULE-SET 缺少策略"))
				continue
			}
			name := strings.TrimSpace(parts[1])
			policy := strings.TrimSpace(parts[2])
			noResolve := ruleHasNoResolve(parts)
			provider, ok := ruleProviders[name]
			if !ok {
				out = append(out, surgeDropNote(rule, "找不到对应的 rule-provider"))
				continue
			}
			if resolved, done := resolveLoonRuleSet(name, provider, policy); done {
				if kept, dropped := keepSurgeReadableRules(resolved); len(kept) > 0 {
					if noResolve {
						kept = applySurgeNoResolve(kept)
					}
					out = append(out, kept...)
					if dropped > 0 {
						out = append(out, fmt.Sprintf("# RULE-SET,%s 展开时跳过 %d 条 Surge 不支持的规则", name, dropped))
					}
					continue
				}
			}
			url, why := surgeRuleSetURL(provider)
			if url == "" {
				out = append(out, surgeDropNote(rule, why))
				continue
			}
			line := fmt.Sprintf("RULE-SET,%s,%s", url, policy)
			if noResolve {
				line += ",no-resolve"
			}
			out = append(out, line)

		case "AND", "OR", "NOT":
			if line, ok := normalizeSurgeLogicRule(rule, ruleProviders); ok {
				out = append(out, line)
			} else {
				out = append(out, surgeDropNote(rule, "逻辑规则里有 Surge 不支持的子规则"))
			}

		default:
			if line, ok := normalizeSurgeRuleLine(rule); ok {
				out = append(out, line)
			} else {
				out = append(out, surgeDropNote(rule, "Surge 无对应规则类型"))
			}
		}
	}
	return out, nil
}

// surgeRuleSetURL 解析不了规则集内容时,给 Surge 的远程地址;返回空串 = 没有可用地址(附原因)。
func surgeRuleSetURL(p ClashRuleProvider) (string, string) {
	url := strings.TrimSpace(p.URL)
	if url == "" {
		return "", "规则集没有地址"
	}
	if strings.HasSuffix(url, ".mrs") {
		return "", "规则集是 .mrs 二进制,Surge 读不了"
	}
	return convertRuleURLToList(url), ""
}

// normalizeSurgeRuleLine 把一条普通 clash 规则改成 Surge 写法;ok=false = Surge 没有对等写法。
func normalizeSurgeRuleLine(rule string) (string, bool) {
	parts := strings.SplitN(rule, ",", 2)
	if len(parts) < 2 {
		return "", false
	}
	raw := strings.TrimSpace(parts[0])
	kw := strings.ToUpper(raw)
	alias, ok := surgeRuleKeywordAlias[kw]
	if !ok || kw == "RULE-SET" {
		return "", false
	}
	if kw == "AND" || kw == "OR" || kw == "NOT" {
		return normalizeSurgeLogicRule(rule, nil)
	}
	if kw == "NETWORK" || kw == "PROTOCOL" {
		seg := strings.SplitN(parts[1], ",", 2)
		seg[0] = strings.ToUpper(strings.TrimSpace(seg[0]))
		return alias + "," + strings.Join(seg, ","), true
	}
	if raw == alias {
		return strings.TrimSpace(rule), true
	}
	return alias + "," + parts[1], true
}

// normalizeSurgeLogicRule 逻辑规则 AND,((子规则),(子规则)),策略:子规则逐个翻译;
// 子规则里的 RULE-SET 引用的是 clash 的 provider 名,换成远程地址。任一子规则 Surge 不认就整条丢。
func normalizeSurgeLogicRule(rule string, providers map[string]ClashRuleProvider) (string, bool) {
	parts := splitRuleTopLevel(strings.TrimSpace(rule))
	if len(parts) < 3 {
		return "", false
	}
	kw := strings.ToUpper(strings.TrimSpace(parts[0]))
	body := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(body, "(") || !strings.HasSuffix(body, ")") {
		return "", false
	}
	subs := splitRuleTopLevel(body[1 : len(body)-1])
	conv := make([]string, 0, len(subs))
	for _, sub := range subs {
		sub = strings.TrimSpace(sub)
		if !strings.HasPrefix(sub, "(") || !strings.HasSuffix(sub, ")") {
			return "", false
		}
		inner := strings.TrimSpace(sub[1 : len(sub)-1])
		innerParts := splitRuleTopLevel(inner)
		innerKW := strings.ToUpper(strings.TrimSpace(innerParts[0]))
		var line string
		switch innerKW {
		case "RULE-SET":
			if len(innerParts) < 2 {
				return "", false
			}
			p, ok := providers[strings.TrimSpace(innerParts[1])]
			if !ok {
				return "", false
			}
			url, _ := surgeRuleSetURL(p)
			if url == "" {
				return "", false
			}
			line = "RULE-SET," + url
		case "AND", "OR", "NOT":
			// 嵌套逻辑规则:补一个占位策略借用同一套翻译,再去掉
			nested, ok := normalizeSurgeLogicRule(inner+",_", providers)
			if !ok {
				return "", false
			}
			line = strings.TrimSuffix(nested, ",_")
		default:
			// 子规则没有策略,补一个占位策略借用单行翻译,再去掉
			l, ok := normalizeSurgeRuleLine(inner + ",_")
			if !ok {
				return "", false
			}
			line = strings.TrimSuffix(l, ",_")
		}
		conv = append(conv, "("+line+")")
	}
	rest := strings.Join(parts[2:], ",")
	return kw + ",(" + strings.Join(conv, ",") + ")," + rest, true
}

// keepSurgeReadableRules 过滤规则集解析器展开出的行,只留 Surge 读得懂的(并翻译关键字)。
func keepSurgeReadableRules(in []string) (kept []string, dropped int) {
	for _, ln := range in {
		if ln = strings.TrimSpace(ln); ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if line, ok := normalizeSurgeRuleLine(ln); ok {
			kept = append(kept, line)
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// applySurgeNoResolve RULE-SET 行尾的 no-resolve 补到展开出来的 IP 类规则上(理由同 applyLoonNoResolve)。
func applySurgeNoResolve(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		kw := strings.ToUpper(strings.TrimSpace(strings.SplitN(ln, ",", 2)[0]))
		if surgeIPRuleKeywords[kw] && !strings.Contains(strings.ToLower(ln), "no-resolve") {
			ln += ",no-resolve"
		}
		out = append(out, ln)
	}
	return out
}

// ruleHasNoResolve 规则尾部选项(第 4 段起)里有没有 no-resolve。
func ruleHasNoResolve(parts []string) bool {
	for _, p := range parts[min(3, len(parts)):] {
		if strings.EqualFold(strings.TrimSpace(p), "no-resolve") {
			return true
		}
	}
	return false
}

// surgeDropNote 丢掉的规则写成注释留在原位:静默丢弃会让人以为规则生效了。
func surgeDropNote(rule, reason string) string {
	return fmt.Sprintf("# 已忽略(%s):%s", reason, strings.TrimSpace(rule))
}
