package substore

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed templates/loon_kelee.lcf
var loonKeleeTemplate string

// BuildCompleteLoonConfig builds a complete Loon configuration from Clash config
func BuildCompleteLoonConfig(clashConfig *ClashConfig, proxies []Proxy) (string, error) {
	var sections []string

	// [General]
	sections = append(sections, buildLoonGeneral(clashConfig))

	// [Proxy]
	proxySection, err := buildLoonProxySection(proxies)
	if err != nil {
		return "", err
	}
	sections = append(sections, proxySection)

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

func buildLoonProxySection(proxies []Proxy) (string, error) {
	lines, err := buildLoonProxyLines(proxies)
	if err != nil {
		return "", err
	}
	if lines != "" {
		return "[Proxy]\n" + lines, nil
	}
	return "[Proxy]", nil
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

func convertRuleURLToList(url string) string {
	if strings.HasSuffix(url, ".yaml") {
		return strings.TrimSuffix(url, ".yaml") + ".list"
	}
	if strings.HasSuffix(url, ".mrs") {
		return strings.TrimSuffix(url, ".mrs") + ".list"
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
					url := provider.URL
					if url != "" {
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
	proxyLines, err := buildLoonProxyLines(proxies)
	if err != nil {
		return "", err
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

func buildLoonProxyLines(proxies []Proxy) (string, error) {
	loonProducer := NewLoonProducer()
	opts := &ProduceOptions{}

	var lines []string
	for _, proxy := range proxies {
		line, err := loonProducer.ProduceOne(proxy, "", opts)
		if err != nil {
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n"), nil
}
