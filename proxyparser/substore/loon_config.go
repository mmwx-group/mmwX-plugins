package substore

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed templates/loon_kelee.lcf
var loonKeleeTemplate string

// BuildCompleteLoonConfig builds a complete Loon configuration from Clash config
func BuildCompleteLoonConfig(clashConfig *ClashConfig, proxies []Proxy) (string, error) {
	var sections []string

	// [General]
	sections = append(sections, buildLoonGeneral(clashConfig))

	// 合法策略名 = 所有节点名 + 所有策略组名。链式代理的首跳必须落在其中,
	// 否则会生成一条指向不存在策略的链,Loon 直接判配置无效。
	knownPolicies := map[string]bool{}
	for _, p := range proxies {
		if n := GetString(p, "name"); n != "" {
			knownPolicies[n] = true
		}
	}
	for _, g := range clashConfig.ProxyGroups {
		if g.Name != "" {
			knownPolicies[g.Name] = true
		}
	}

	// [Proxy]
	proxySection, chains, err := buildLoonProxySection(proxies, knownPolicies)
	if err != nil {
		return "", err
	}
	sections = append(sections, proxySection)

	// [Proxy Chain] —— 只有存在链式节点时才输出这一段
	if chainSection := buildLoonProxyChains(chains); chainSection != "" {
		sections = append(sections, chainSection)
	}

	// [Proxy Group]
	sections = append(sections, buildLoonProxyGroups(clashConfig.ProxyGroups))

	// [Rule]
	sections = append(sections, buildLoonRules(clashConfig.Rules, clashConfig.RuleProviders))

	return strings.Join(sections, "\n\n"), nil
}

func buildLoonGeneral(_ *ClashConfig) string {
	var lines []string
	lines = append(lines, "[General]")
	lines = append(lines, "ip-mode = dual")
	lines = append(lines, "dns-server = system, 119.29.29.29, 223.5.5.5")
	lines = append(lines, "sni-sniffing = true")
	lines = append(lines, "disable-stun = false")
	lines = append(lines, "dns-reject-mode = LoopbackIP")
	lines = append(lines, "domain-reject-mode = DNS")
	lines = append(lines, "udp-fallback-mode = REJECT")
	lines = append(lines, "wifi-access-http-port = 7222")
	lines = append(lines, "wifi-access-socks5-port = 7221")
	lines = append(lines, "allow-wifi-access = false")
	lines = append(lines, "interface-mode = auto")
	lines = append(lines, "test-timeout = 5")
	lines = append(lines, "disconnect-on-policy-change = true")
	lines = append(lines, "switch-node-after-failure-times = 3")
	lines = append(lines, "internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204")
	lines = append(lines, "proxy-test-url = http://www.gstatic.com/generate_204")
	lines = append(lines, "resource-parser = https://gitlab.com/sub-store/Sub-Store/-/releases/permalink/latest/downloads/sub-store-parser.loon.min.js")
	lines = append(lines, "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.]qq.com")
	lines = append(lines, "bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32")

	return strings.Join(lines, "\n")
}

// loonChain 一条链式代理:chain 名沿用**原节点名**,落地节点改名后另行输出。
//
// 这样各策略组不用改:它们照旧引用原名,而原名现在指向的是「先走首跳、再走落地」
// 的这条链。反过来做(链另起新名)就得同步改所有组的成员列表,极易漏。
type loonChain struct {
	name     string // 原节点名 = 链名
	firstHop string // clash 里的 dialer-proxy(节点名或策略组名)
	landing  string // 落地节点在 [Proxy] 里的新名字
	udp      bool
}

func buildLoonProxySection(proxies []Proxy, knownPolicies map[string]bool) (string, []loonChain, error) {
	lines, chains, err := buildLoonProxyLines(proxies, knownPolicies)
	if err != nil {
		return "", nil, err
	}
	if lines != "" {
		return "[Proxy]\n" + lines, chains, nil
	}
	return "[Proxy]", chains, nil
}

func buildLoonProxyChains(chains []loonChain) string {
	if len(chains) == 0 {
		return ""
	}
	lines := []string{"[Proxy Chain]"}
	for _, c := range chains {
		line := fmt.Sprintf("%s = %s, %s", c.name, c.firstHop, c.landing)
		if c.udp {
			line += ", udp=true"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func buildLoonProxyGroups(groups []ClashProxyGroup) string {
	var lines []string
	lines = append(lines, "[Proxy Group]")

	for _, g := range groups {
		var regexFilters []string
		var normalProxies []string
		for _, proxy := range g.Proxies {
			if IsRegexProxyPattern(proxy) {
				regexFilters = append(regexFilters, proxy)
			} else {
				normalProxies = append(normalProxies, proxy)
			}
		}

		loonType := convertToLoonGroupType(g.Type)
		url := g.URL
		if url == "" {
			url = "http://www.gstatic.com/generate_204"
		}
		interval := g.Interval
		if interval <= 0 {
			interval = 300
		}

		var line string

		switch loonType {
		case "url-test", "fallback":
			if len(regexFilters) > 0 {
				filter := MergeRegexFilters(regexFilters)
				if len(normalProxies) > 0 {
					line = fmt.Sprintf("%s = %s, %s, url = %s, interval = %d, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png",
						g.Name, loonType, strings.Join(normalProxies, ", "), url, interval)
				} else {
					line = fmt.Sprintf("%s = %s, NameRegexFilter = %s, url = %s, interval = %d, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png",
						g.Name, loonType, filter, url, interval)
				}
			} else {
				proxies := normalProxies
				if len(proxies) == 0 {
					proxies = []string{"DIRECT"}
				}
				line = fmt.Sprintf("%s = %s, %s, url = %s, interval = %d, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png",
					g.Name, loonType, strings.Join(proxies, ", "), url, interval)
			}
			if g.Tolerance > 0 && loonType == "url-test" {
				line += fmt.Sprintf(", tolerance = %d", g.Tolerance)
			}

		case "select":
			proxies := normalProxies
			if len(regexFilters) > 0 {
				filter := MergeRegexFilters(regexFilters)
				if len(proxies) > 0 {
					line = fmt.Sprintf("%s = select, %s, NameRegexFilter = %s, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png",
						g.Name, strings.Join(proxies, ", "), filter)
				} else {
					line = fmt.Sprintf("%s = select, NameRegexFilter = %s, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png",
						g.Name, filter)
				}
			} else {
				if len(proxies) == 0 {
					proxies = []string{"DIRECT"}
				}
				line = fmt.Sprintf("%s = select, %s, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png",
					g.Name, strings.Join(proxies, ", "))
			}

		case "load-balance":
			proxies := normalProxies
			if len(proxies) == 0 {
				proxies = []string{"DIRECT"}
			}
			algorithm := "pcc"
			if g.Strategy == "round-robin" {
				algorithm = "round-robin"
			}
			line = fmt.Sprintf("%s = load-balance, %s, url = %s, interval = %d, algorithm = %s, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Available.png",
				g.Name, strings.Join(proxies, ", "), url, interval, algorithm)

		default:
			proxies := normalProxies
			if len(proxies) == 0 {
				proxies = []string{"DIRECT"}
			}
			line = fmt.Sprintf("%s = select, %s, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png",
				g.Name, strings.Join(proxies, ", "))
		}

		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}

func convertToLoonGroupType(clashType string) string {
	switch strings.ToLower(clashType) {
	case "select":
		return "select"
	case "url-test":
		return "url-test"
	case "fallback":
		return "fallback"
	case "load-balance":
		return "load-balance"
	case "relay":
		return "select"
	default:
		return "select"
	}
}

// LoonRuleSetResolver 把一个 clash rule-provider 解析成可直接写进 Loon [Rule] 的行。
//
// 为什么要注入而不是在这里做:正确解析必须**真的拿到规则内容**(尤其 .mrs 是二进制,
// 得去取同目录的 .yaml 再按 behavior 转换),而这个模块是纯函数、不联网。
// 主控那边有 SSRF 安全的抓取客户端和缓存,由它实现。
//
// 返回 (lines, true) 表示已解析,调用方直接内联这些行;(nil, false) 表示解析不了。
type LoonRuleSetResolver func(name string, provider ClashRuleProvider, policy string) ([]string, bool)

var (
	loonResolverMu sync.RWMutex
	loonResolver   LoonRuleSetResolver
)

// SetLoonRuleSetResolver 注入解析器。主控启动时装配一次;不注入则退化为旧行为。
func SetLoonRuleSetResolver(r LoonRuleSetResolver) {
	loonResolverMu.Lock()
	defer loonResolverMu.Unlock()
	loonResolver = r
}

func resolveLoonRuleSet(name string, p ClashRuleProvider, policy string) ([]string, bool) {
	loonResolverMu.RLock()
	r := loonResolver
	loonResolverMu.RUnlock()
	if r == nil {
		return nil, false
	}
	return r(name, p, policy)
}

// convertRuleURLToList 猜同目录下的 .list 版本。
//
// **只对 .yaml 这么猜**:主流规则仓库(Loyalsoldier 等)确实同时发布 .list,
// 这条启发式一直是有效的。而 .mrs 不同 —— 它是二进制格式,很多仓库根本没有同名
// .list,改扩展名要么 404、要么给 Loon 一个它读不懂的二进制(用户实报)。
// 所以 .mrs 不再猜:有解析器就内联真实规则,没有就整条跳过,绝不产出错的地址。
func convertRuleURLToList(url string) string {
	if strings.HasSuffix(url, ".yaml") {
		return strings.TrimSuffix(url, ".yaml") + ".list"
	}
	return url
}

// loonRuleKeywordAlias:clash 规则关键字 → Loon 规则关键字。
//
// **这份名单的依据是 Loon 官方文档(https://nsloon.app/docs/Rule/ 各子页),不是 Surge。**
// 以前这里是直接从 surge_template.go 抄的白名单,于是混进了三个 Surge 有、Loon 没有的
// 关键字,原样透传后 Loon 读不懂、整行失效(用户实报的「规则丢失」):
//
//	SRC-IP-CIDR   Loon 的 IP 规则只有 IP-CIDR / IP-CIDR6 / GEOIP / IP-ASN → 无对等,丢弃
//	PROCESS-NAME  Loon 跑在 iOS/tvOS,没有进程规则                        → 无对等,丢弃
//	DST-PORT      Loon 拼作 DEST-PORT                                    → 改名,别丢
//
// 不在这张表里的关键字(GEOSITE、DOMAIN-REGEX、IP-SUFFIX、SRC-GEOIP…)一律丢弃:
// 产出 Loon 读不懂的行严格劣于不产出 —— 前者会让用户以为规则生效了。
// GEOSITE 另有展开路径,见 buildLoonRules。
var loonRuleKeywordAlias = map[string]string{
	// 域名规则 https://nsloon.app/docs/Rule/domain_rule/
	"DOMAIN": "DOMAIN", "DOMAIN-SUFFIX": "DOMAIN-SUFFIX", "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
	// IP 规则 https://nsloon.app/docs/Rule/ip_rule/
	"IP-CIDR": "IP-CIDR", "IP-CIDR6": "IP-CIDR6", "IP6-CIDR": "IP-CIDR6",
	"GEOIP": "GEOIP", "IP-ASN": "IP-ASN",
	// 端口规则:clash 叫 DST-PORT,Loon 叫 DEST-PORT
	"SRC-PORT": "SRC-PORT", "DST-PORT": "DEST-PORT", "DEST-PORT": "DEST-PORT",
	// HTTP 规则 https://nsloon.app/docs/Rule/http_rule/
	"URL-REGEX": "URL-REGEX", "USER-AGENT": "USER-AGENT",
	// 协议规则 https://nsloon.app/docs/Rule/protocol_rule/
	// clash 的 NETWORK,udp 等价于 Loon 的 PROTOCOL,UDP —— 值要大写,见 normalizeLoonRuleLine
	"PROTOCOL": "PROTOCOL", "NETWORK": "PROTOCOL",
	// 逻辑规则 https://nsloon.app/docs/Rule/logic_rule/
	"AND": "AND", "OR": "OR", "NOT": "NOT",
	// 兜底 https://nsloon.app/docs/Rule/final_rule/
	"FINAL": "FINAL",
}

// 逻辑规则形如 AND,((DOMAIN,x),(DEST-PORT,443)),策略 —— 括号里嵌的子规则关键字
// 同样得是 Loon 认识的,所以要逐个抠出来核对。
var loonLogicSubRuleKeyword = regexp.MustCompile(`\(([A-Za-z0-9-]+),`)

// normalizeLoonRuleLine 把一条 clash 规则整成 Loon 能执行的写法。
// ok=false 表示 Loon 没有对等写法,调用方应当丢弃(并留痕)。
func normalizeLoonRuleLine(rule string) (string, bool) {
	parts := strings.SplitN(rule, ",", 2)
	if len(parts) < 2 {
		return "", false
	}
	raw := strings.TrimSpace(parts[0])
	kw := strings.ToUpper(raw)

	if kw == "AND" || kw == "OR" || kw == "NOT" {
		return normalizeLoonLogicRule(rule)
	}

	alias, ok := loonRuleKeywordAlias[kw]
	if !ok {
		return "", false
	}
	if kw == "NETWORK" {
		// clash 写小写(tcp/udp),Loon 的 PROTOCOL 取值是大写的
		seg := strings.SplitN(parts[1], ",", 2)
		seg[0] = strings.ToUpper(strings.TrimSpace(seg[0]))
		return alias + "," + strings.Join(seg, ","), true
	}
	if raw == alias {
		// 关键字没变就原样保留:规则后面还可能跟 no-resolve 之类的选项,
		// 重新拼装只会平白改动排版、徒增出错面。
		return strings.TrimSpace(rule), true
	}
	return alias + "," + parts[1], true
}

func normalizeLoonLogicRule(rule string) (string, bool) {
	supported := true
	out := loonLogicSubRuleKeyword.ReplaceAllStringFunc(strings.TrimSpace(rule), func(m string) string {
		alias, ok := loonRuleKeywordAlias[strings.ToUpper(m[1:len(m)-1])]
		if !ok {
			// 子规则里有 Loon 不认识的关键字,整条逻辑规则都没法执行
			supported = false
			return m
		}
		return "(" + alias + ","
	})
	if !supported {
		return "", false
	}
	return out, true
}

// loonDropNote 把丢掉的规则写成注释留在 [Rule] 段里。
//
// 静默丢弃会让用户「规则莫名其妙不生效」却无从查起(这正是用户实报的现象);
// `#` 开头的行 Loon 会忽略,不影响配置加载,但一眼能看出少了什么、为什么少。
func loonDropNote(rule, reason string) string {
	return fmt.Sprintf("# 已忽略(%s):%s", reason, strings.TrimSpace(rule))
}

// keepLoonReadableRules 过滤解析器/规则集返回的行。
//
// 解析器是外部注入的(主控实现),它按 clash 的 classical 行为展开时可能带出
// DOMAIN-REGEX、PROCESS-NAME 这种 Loon 没有的规则。内联进 [Rule] 前统一过一道,
// 保证「写进去的每一行 Loon 都读得懂」这条不变量只由本文件负责。
func keepLoonReadableRules(in []string) (kept []string, dropped int) {
	for _, ln := range in {
		if ln = strings.TrimSpace(ln); ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if line, ok := normalizeLoonRuleLine(ln); ok {
			kept = append(kept, line)
		} else {
			dropped++
		}
	}
	return kept, dropped
}

// loonIPRuleKeywords 认 IP 类规则 —— 只有它们才会触发 DNS 解析,也只有它们吃 no-resolve。
var loonIPRuleKeywords = map[string]bool{
	"IP-CIDR": true, "IP-CIDR6": true, "GEOIP": true, "IP-ASN": true,
}

// applyLoonNoResolve 把 RULE-SET 行尾的 no-resolve 补到展开出来的 IP 类规则上。
//
// clash 写 `RULE-SET,cnip,DIRECT,no-resolve` 时,no-resolve 挂在 RULE-SET 这一行上;
// 而我们把规则集展开成了一条条 `IP-CIDR,...,DIRECT` 内联进 [Rule] —— 标志就留在原地丢了。
// 后果不是「规则失效」而是更隐蔽的**行为反转**:Loon 会对每条 IP 规则先做 DNS 解析,
// 域名请求在命中直连 IP 段前先被解析一次,既慢又可能把本该直连的查询送出去。
//
// 只补 IP 类:域名规则(DOMAIN/DOMAIN-SUFFIX/…)本来就不解析,给它加 no-resolve 是语法噪音。
// 已经自带的不重复加 —— 规则集内容里本身可能就带着。
func applyLoonNoResolve(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		kw := strings.ToUpper(strings.TrimSpace(strings.SplitN(ln, ",", 2)[0]))
		if loonIPRuleKeywords[kw] && !strings.Contains(strings.ToLower(ln), "no-resolve") {
			ln += ",no-resolve"
		}
		out = append(out, ln)
	}
	return out
}

// loonRuleHasNoResolve 看规则行的尾部选项里有没有 no-resolve(parts[3] 起)。
func loonRuleHasNoResolve(parts []string) bool {
	for _, p := range parts[min(3, len(parts)):] {
		if strings.EqualFold(strings.TrimSpace(p), "no-resolve") {
			return true
		}
	}
	return false
}

// GEOSITE 在 Loon 里**根本不存在**(域名规则只有 DOMAIN / DOMAIN-SUFFIX /
// DOMAIN-KEYWORD),只能把类目展开成域名规则。类目名 → URL 走 MetaCubeX/meta-rules-dat
// —— 它是 mihomo 官方的 geo 数据仓库,geosite 类目名与 clash 侧**完全同名**,
// 直接拼文件名即可,不需要维护映射表(映射表只会随上游新增类目而过期):
//
//	geo/geosite/<类目>.list            每行一个域名(`+.x` 表示含子域)。交给
//	                                   resolver 按 behavior=domain 展开成
//	                                   DOMAIN / DOMAIN-SUFFIX 内联进 [Rule],最准。
//	geo/geosite/classical/<类目>.list  每行本身就是 `DOMAIN-SUFFIX,x` 这种规则行,
//	                                   正好是 Loon [Remote Rule] 要的格式 ——
//	                                   内联不了(没装 resolver / 抓不到 / 类目太大)时拿它兜底。
//
// 类目名统一小写:上游文件名全小写,而 clash 模板里偶有写成 GEOSITE,CN 的。
const (
	geositeDomainListBase    = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/"
	geositeClassicalListBase = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/"
)

func geositeDomainListURL(name string) string    { return geositeDomainListBase + name + ".list" }
func geositeClassicalListURL(name string) string { return geositeClassicalListBase + name + ".list" }

func buildLoonRules(rules []string, ruleProviders map[string]ClashRuleProvider) string {
	var lines []string
	lines = append(lines, "[Rule]")

	// Collect remote rules from RULE-SET references
	var remoteRules []string

	for _, rule := range rules {
		parts := strings.Split(rule, ",")
		if len(parts) < 2 {
			continue
		}

		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))

		switch ruleType {
		case "MATCH":
			lines = append(lines, fmt.Sprintf("FINAL,%s", strings.TrimSpace(parts[1])))

		case "GEOSITE":
			if len(parts) < 3 {
				lines = append(lines, loonDropNote(rule, "GEOSITE 缺少策略"))
				continue
			}
			name := strings.ToLower(strings.TrimSpace(parts[1]))
			policy := strings.TrimSpace(parts[2])
			if name == "" || policy == "" {
				lines = append(lines, loonDropNote(rule, "GEOSITE 类目名或策略为空"))
				continue
			}
			// 1) 先走 resolver:把类目真的展开成域名规则内联进来,和 RULE-SET 同一条路
			//    (同一套缓存 + SSRF 安全抓取客户端)。
			if resolved, done := resolveLoonRuleSet("geosite:"+name, ClashRuleProvider{
				Type:     "http",
				Behavior: "domain",
				Format:   "text",
				URL:      geositeDomainListURL(name),
			}, policy); done {
				if kept, dropped := keepLoonReadableRules(resolved); len(kept) > 0 {
					lines = append(lines, kept...)
					if dropped > 0 {
						lines = append(lines, fmt.Sprintf("# GEOSITE,%s 展开时跳过 %d 条 Loon 不支持的规则", name, dropped))
					}
					continue
				}
			}
			// 2) 退化成 [Remote Rule]:classical 清单本身就是 Loon 规则行,拿来即用。
			//    类目不存在时 Loon 只是这条远程规则拉不到(配置照常加载),
			//    比整条规则凭空消失强。
			remoteRules = append(remoteRules, fmt.Sprintf("%s, policy=%s, tag=%s, enabled=true",
				geositeClassicalListURL(name), policy, "geosite-"+name))

		case "RULE-SET":
			if len(parts) < 3 {
				lines = append(lines, loonDropNote(rule, "RULE-SET 缺少策略"))
				continue
			}
			ruleSetName := strings.TrimSpace(parts[1])
			policy := strings.TrimSpace(parts[2])

			provider, ok := ruleProviders[ruleSetName]
			if !ok {
				lines = append(lines, loonDropNote(rule, "找不到对应的 rule-provider"))
				continue
			}
			// 先给解析器机会:能拿到真实规则就直接内联,最准。
			if resolved, done := resolveLoonRuleSet(ruleSetName, provider, policy); done {
				if kept, dropped := keepLoonReadableRules(resolved); len(kept) > 0 {
					if loonRuleHasNoResolve(parts) {
						kept = applyLoonNoResolve(kept)
					}
					lines = append(lines, kept...)
					if dropped > 0 {
						lines = append(lines, fmt.Sprintf("# RULE-SET,%s 展开时跳过 %d 条 Loon 不支持的规则", ruleSetName, dropped))
					}
					continue
				}
			}
			url := provider.URL
			// .mrs 是二进制,没解析器时整条跳过 —— 猜一个 .list 地址
			// 只会得到 404 或读不懂的二进制,还不如让这条规则不生效。
			if url == "" || strings.HasSuffix(url, ".mrs") {
				lines = append(lines, loonDropNote(rule, "规则集内容拿不到(.mrs 二进制或地址为空)"))
				continue
			}
			url = convertRuleURLToList(url)
			remoteRules = append(remoteRules, fmt.Sprintf("%s, policy=%s, tag=%s, enabled=true",
				url, policy, ruleSetName))

		default:
			// 关键字要么翻译、要么丢弃 —— 绝不原样透传:Loon 读不懂的行等于规则静默失效。
			if line, ok := normalizeLoonRuleLine(rule); ok {
				lines = append(lines, line)
			} else {
				lines = append(lines, loonDropNote(rule, "Loon 无对应规则类型"))
			}
		}
	}

	result := strings.Join(lines, "\n")

	// Append [Remote Rule] section if there are rule-providers
	if len(remoteRules) > 0 {
		result += "\n\n[Remote Rule]\n"
		result += strings.Join(remoteRules, "\n")
	}

	return result
}

// BuildLoonKeleeConfig uses the kelee template and fills in proxy nodes
//
// 薄壳:等价于不带任何外部策略组的 BuildLoonKeleeConfigWithPolicies。
func BuildLoonKeleeConfig(proxies []Proxy) (string, error) {
	return BuildLoonKeleeConfigWithPolicies(proxies, nil)
}

// BuildLoonKeleeConfigWithPolicies 用 kelee 模板生成配置,并额外承认 extraPolicies 里的策略名。
//
// 为什么需要它:链式节点的首跳(clash 的 dialer-proxy)常常是**中转组**这种策略组名,
// 而 kelee 模板自带的组名在这里看不到,于是首跳一律校验不过、整条链被静默吞掉
// (clash-to-loon-kelee 下用户实报的「中转链没了」)。
//
// **契约 —— 首跳必须在输出里真实存在**,否则只是把「静默丢链」换成「Loon 整份拒载」。
// 所以本函数不只把名字加进白名单,还负责让它有主:
//
//   - 名字已经是 kelee 模板自带的组(解析模板 [Proxy Group] 得到)→ 直接采信,不重复渲染;
//   - 名字是传进来的某个节点名 → 直接采信;
//   - 其余(典型就是 clash 侧的中转组)**且确实被某个节点当作首跳** → 本函数把它渲染成
//     一条 `名字 = select, …` 追加进 [Proxy Group]。成员取所有**非链式**节点:
//     这里拿不到中转组原本的成员表,让用户在组里自选首跳,好过整条链消失;
//     把链式节点放进来则会绕回链自身。
//
// 没被任何节点当首跳的名字只进白名单、不渲染 —— 没有引用就不会悬空,也就不必往
// 模板里塞一个没人用的组。调用方因此可以把 clash 侧**全部**策略组名一股脑传进来,
// 不用自己挑,也不用自己往模板里塞组。
func BuildLoonKeleeConfigWithPolicies(proxies []Proxy, extraPolicies []string) (string, error) {
	known := map[string]bool{}
	firstHops := map[string]bool{}
	for _, p := range proxies {
		if n := GetString(p, "name"); n != "" {
			known[n] = true
		}
		hop := GetString(p, "dialer-proxy")
		if hop == "" {
			hop = GetString(p, "underlying-proxy")
		}
		if hop != "" {
			firstHops[hop] = true
		}
	}

	templateGroups := parseLoonTemplateGroupNames(loonKeleeTemplate)
	var needRender []string
	seen := map[string]bool{}
	for _, name := range extraPolicies {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if firstHops[name] && !templateGroups[name] && !known[name] {
			needRender = append(needRender, name)
		}
		known[name] = true
	}
	groupLines := buildLoonExtraPolicyGroups(needRender, proxies)

	proxyLines, chains, err := buildLoonProxyLines(proxies, known)
	if err != nil {
		return "", err
	}
	if chainSection := buildLoonProxyChains(chains); chainSection != "" {
		proxyLines += "\n\n" + chainSection
	}

	lines := strings.Split(loonKeleeTemplate, "\n")
	var result []string
	inserted := false
	groupsInserted := false

	for _, line := range lines {
		result = append(result, line)
		switch {
		case !inserted && strings.TrimSpace(line) == "[Proxy]":
			if proxyLines != "" {
				result = append(result, proxyLines)
			}
			inserted = true
		case !groupsInserted && strings.TrimSpace(line) == "[Proxy Group]":
			if len(groupLines) > 0 {
				result = append(result, groupLines...)
			}
			groupsInserted = true
		}
	}

	return strings.Join(result, "\n"), nil
}

// parseLoonTemplateGroupNames 抠出模板 [Proxy Group] 段里已有的组名(`名字=类型, …` 等号左边)。
// 只用于去重 —— 模板里已经有的组再渲染一遍就是重名组。
func parseLoonTemplateGroupNames(tpl string) map[string]bool {
	names := map[string]bool{}
	section := ""
	for _, ln := range strings.Split(tpl, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = t
			continue
		}
		if section != "[Proxy Group]" || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if i := strings.Index(t, "="); i > 0 {
			names[strings.TrimSpace(t[:i])] = true
		}
	}
	return names
}

// buildLoonExtraPolicyGroups 给「只知道名字、模板里又没有」的策略组补一条 select 行,
// 让引用它的链有主。成员排除链式节点,避免首跳绕回链自身。
func buildLoonExtraPolicyGroups(names []string, proxies []Proxy) []string {
	if len(names) == 0 {
		return nil
	}
	var members []string
	for _, p := range proxies {
		if GetString(p, "dialer-proxy") != "" || GetString(p, "underlying-proxy") != "" {
			continue
		}
		if n := GetString(p, "name"); n != "" {
			members = append(members, n)
		}
	}
	if len(members) == 0 {
		members = []string{"DIRECT"}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, fmt.Sprintf("%s = select, %s, img-url = https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png",
			n, strings.Join(members, ", ")))
	}
	return out
}

// buildLoonProxyLines 生成 [Proxy] 各行,并把带 dialer-proxy 的节点拆成
// 「落地节点 + 一条链」。
//
// 不处理 dialer-proxy 的话,Loon 只会拿到一个普通落地节点 —— 流量直连落地、
// 绕过入口,和 clash 侧的行为完全不同(用户实报)。
func buildLoonProxyLines(proxies []Proxy, knownPolicies map[string]bool) (string, []loonChain, error) {
	loonProducer := NewLoonProducer()
	opts := &ProduceOptions{}

	var lines []string
	var chains []loonChain
	for _, proxy := range proxies {
		name := GetString(proxy, "name")
		firstHop := GetString(proxy, "dialer-proxy")
		if firstHop == "" {
			firstHop = GetString(proxy, "underlying-proxy")
		}
		// 首跳指向不存在的策略就退回普通节点:宁可少一跳,也不能产出
		// 让 Loon 整份拒载的悬空引用。
		chained := name != "" && firstHop != "" && firstHop != name && knownPolicies[firstHop]

		out := proxy
		if chained {
			// 复制一份再改名 —— 调用方传进来的 map 不该被就地改写。
			out = make(Proxy, len(proxy))
			for k, v := range proxy {
				out[k] = v
			}
			out["name"] = name + " [落地]"
		}
		line, err := loonProducer.ProduceOne(out, "", opts)
		if err != nil {
			continue
		}
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if chained {
			chains = append(chains, loonChain{
				name:     name,
				firstHop: firstHop,
				landing:  GetString(out, "name"),
				udp:      GetBool(proxy, "udp"),
			})
		}
	}
	return strings.Join(lines, "\n"), chains, nil
}

// BuildLoonProxySections 给「模板注入」用:把节点渲染成 [Proxy] 段的行,
// 并把带 dialer-proxy 的节点拆出 [Proxy Chain] 段的行(不含段头,由调用方拼)。
//
// extraPolicies 是模板里已定义的策略组名。链的首跳常常指向模板自带的组
// (比如「🚀 手动选择」),不把这些名字传进来的话,那些链会因为「首跳未知」
// 被丢掉 —— 而模板场景下这恰恰是最常见的一种。
func BuildLoonProxySections(proxies []Proxy, extraPolicies []string) (string, string, error) {
	known := map[string]bool{}
	for _, p := range proxies {
		if n := GetString(p, "name"); n != "" {
			known[n] = true
		}
	}
	for _, n := range extraPolicies {
		if n != "" {
			known[n] = true
		}
	}
	lines, chains, err := buildLoonProxyLines(proxies, known)
	if err != nil {
		return "", "", err
	}
	chainSection := buildLoonProxyChains(chains)
	chainSection = strings.TrimPrefix(chainSection, "[Proxy Chain]\n")
	if chainSection == "[Proxy Chain]" {
		chainSection = ""
	}
	return lines, chainSection, nil
}
