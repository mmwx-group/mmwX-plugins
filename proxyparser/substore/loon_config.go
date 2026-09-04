package substore

import (
	_ "embed"
	"fmt"
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

		ruleType := strings.TrimSpace(parts[0])

		switch ruleType {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
			"GEOIP", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "IP-ASN":
			lines = append(lines, rule)

		case "MATCH":
			if len(parts) >= 2 {
				lines = append(lines, fmt.Sprintf("FINAL,%s", strings.TrimSpace(parts[1])))
			}

		case "RULE-SET":
			if len(parts) >= 3 {
				ruleSetName := strings.TrimSpace(parts[1])
				policy := strings.TrimSpace(parts[2])

				if provider, ok := ruleProviders[ruleSetName]; ok {
					// 先给解析器机会:能拿到真实规则就直接内联,最准。
					if resolved, done := resolveLoonRuleSet(ruleSetName, provider, policy); done {
						lines = append(lines, resolved...)
						continue
					}
					url := provider.URL
					// .mrs 是二进制,没解析器时整条跳过 —— 猜一个 .list 地址
					// 只会得到 404 或读不懂的二进制,还不如让这条规则不生效。
					if url != "" && !strings.HasSuffix(url, ".mrs") {
						url = convertRuleURLToList(url)
						remoteRules = append(remoteRules, fmt.Sprintf("%s, policy=%s, tag=%s, enabled=true",
							url, policy, ruleSetName))
					}
				}
			}

		default:
			lines = append(lines, rule)
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
func BuildLoonKeleeConfig(proxies []Proxy) (string, error) {
	// kelee 模板自带策略组,它们的名字**这里看不到** —— 所以只把「首跳是另一个节点」
	// 的链认下来;首跳指向模板里某个组名时无法校验,宁可退回普通节点,
	// 也不产出会让 Loon 整份拒载的悬空引用。
	nodeNames := map[string]bool{}
	for _, p := range proxies {
		if n := GetString(p, "name"); n != "" {
			nodeNames[n] = true
		}
	}
	proxyLines, chains, err := buildLoonProxyLines(proxies, nodeNames)
	if err != nil {
		return "", err
	}
	if chainSection := buildLoonProxyChains(chains); chainSection != "" {
		proxyLines += "\n\n" + chainSection
	}

	lines := strings.Split(loonKeleeTemplate, "\n")
	var result []string
	inserted := false

	for _, line := range lines {
		result = append(result, line)
		if !inserted && strings.TrimSpace(line) == "[Proxy]" {
			if proxyLines != "" {
				result = append(result, proxyLines)
			}
			inserted = true
		}
	}

	return strings.Join(result, "\n"), nil
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
