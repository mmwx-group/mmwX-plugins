package substore

import (
	"encoding/json"
	"fmt"
	"github.com/MMWOrg/mmwX-plugins/proxyparser/logger"
	"regexp"
	"strings"
)

// StashProducer implements Stash format converter
type StashProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewStashProducer creates a new Stash producer
func NewStashProducer() *StashProducer {
	return &StashProducer{
		producerType: "stash",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *StashProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Stash format
func (p *StashProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	supportedSSCiphers := map[string]bool{
		"aes-128-gcm":             true,
		"aes-192-gcm":             true,
		"aes-256-gcm":             true,
		"aes-128-cfb":             true,
		"aes-192-cfb":             true,
		"aes-256-cfb":             true,
		"aes-128-ctr":             true,
		"aes-192-ctr":             true,
		"aes-256-ctr":             true,
		"rc4-md5":                 true,
		"chacha20-ietf":           true,
		"xchacha20":               true,
		"chacha20-ietf-poly1305":  true,
		"xchacha20-ietf-poly1305": true,
		"2022-blake3-aes-128-gcm": true,
		"2022-blake3-aes-256-gcm": true,
	}

	var result []Proxy
	for _, proxy := range proxies {
		proxyType := p.helper.GetProxyType(proxy)
		network := GetString(proxy, "network")

		// 镜像 JS: 当 include-unsupported-proxy 开启时, 所有节点直接放行, 不做任何过滤.
		// (JS stash.js 第 19 行: `if (opts['include-unsupported-proxy']) return true;`)
		shouldSkip := false
		if !opts.IncludeUnsupportedProxy {
			switch {
			// 不支持的协议类型 / 不支持的 SS cipher / snell v4+
			// (JS stash.js 第 20-59 行, 合并为一个判断分支)
			case !p.isSupportedType(proxyType),
				proxyType == "ss" && !supportedSSCiphers[GetString(proxy, "cipher")],
				proxyType == "snell" && GetInt(proxy, "version") >= 4:
				shouldSkip = true
				logger.Info("[Stash] 跳过不支持的节点(类型/cipher/snell版本)",
					"name", GetString(proxy, "name"), "type", proxyType)

			// SS v2ray-plugin 仅支持 websocket 模式 (JS 第 62-64 行)
			case !stashSupportsSSV2rayPluginMode(proxy, "websocket"):
				shouldSkip = true
				logger.Info("[Stash] 跳过SS v2ray-plugin非websocket模式节点", "name", GetString(proxy, "name"))

			// vless + reality-opts: 仅当存在 network 且 network != tcp 时跳过 (JS 第 66-72 行)
			case proxyType == "vless" && IsPresent(proxy, "reality-opts") && network != "" && network != "tcp":
				shouldSkip = true
				logger.Info("[Stash] 跳过VLESS reality节点(network非tcp)", "name", GetString(proxy, "name"), "network", network)

			// anytls: 存在 network 时, network 非 tcp, 或 tcp+reality, 均跳过 (JS 第 73-80 行)
			case proxyType == "anytls" && network != "" && (network != "tcp" || IsPresent(proxy, "reality-opts")):
				shouldSkip = true
				logger.Info("[Stash] 跳过anytls节点(network/reality不支持)", "name", GetString(proxy, "name"), "network", network)

			// xhttp 网络不支持 (JS 第 81-82 行)
			case network == "xhttp":
				shouldSkip = true
				logger.Info("[Stash] 跳过xhttp网络节点", "name", GetString(proxy, "name"))

			// vless encryption 必须为空或 none (JS 第 83-88 行)
			case proxyType == "vless" && GetString(proxy, "encryption") != "" && GetString(proxy, "encryption") != "none":
				shouldSkip = true
				logger.Info("[Stash] 跳过VLESS节点(encryption必须为none)", "name", GetString(proxy, "name"), "encryption", GetString(proxy, "encryption"))

			// ws + v2ray-http-upgrade 不支持 (JS 第 89-93 行)
			case network == "ws" && GetBool(GetMap(proxy, "ws-opts"), "v2ray-http-upgrade"):
				shouldSkip = true
				logger.Info("[Stash] 跳过ws+v2ray-http-upgrade节点", "name", GetString(proxy, "name"))
			}
		}

		if shouldSkip {
			continue
		}

		transformed := p.helper.CloneProxy(proxy)

		// VMess transformations
		if proxyType == "vmess" {
			// Handle aead
			if IsPresent(transformed, "aead") {
				if GetBool(transformed, "aead") {
					transformed["alterId"] = 0
				}
				delete(transformed, "aead")
			}

			// sni -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}

			// Cipher 规范化 (镜像 JS normalizeClashVmessSecurity):
			// 小写去空格, chacha20-ietf-poly1305 归一为 chacha20-poly1305,
			// 仅保留 auto/aes-128-gcm/chacha20-poly1305/none, 其余回退 auto.
			transformed["cipher"] = stashNormalizeVmessCipher(GetString(transformed, "cipher"))
		}

		// TUIC transformations
		if proxyType == "tuic" {
			// Ensure alpn is array
			if IsPresent(transformed, "alpn") {
				alpnVal := transformed["alpn"]
				if alpnSlice, ok := alpnVal.([]interface{}); ok {
					transformed["alpn"] = alpnSlice
				} else if alpnStr, ok := alpnVal.(string); ok {
					transformed["alpn"] = []string{alpnStr}
				}
			} else {
				transformed["alpn"] = []string{"h3"}
			}

			// tfo -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
				delete(transformed, "tfo")
			}

			// Default version
			token := GetString(transformed, "token")
			if token == "" && !IsPresent(transformed, "version") {
				transformed["version"] = 5
			}
		}

		// Hysteria transformations
		if proxyType == "hysteria" {
			// auth_str -> auth-str
			if IsPresent(transformed, "auth_str") && !IsPresent(transformed, "auth-str") {
				transformed["auth-str"] = GetString(transformed, "auth_str")
			}

			// Ensure alpn is array
			if IsPresent(transformed, "alpn") {
				alpnVal := transformed["alpn"]
				if alpnSlice, ok := alpnVal.([]interface{}); ok {
					transformed["alpn"] = alpnSlice
				} else if alpnStr, ok := alpnVal.(string); ok {
					transformed["alpn"] = []string{alpnStr}
				}
			}

			// tfo -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
				delete(transformed, "tfo")
			}

			// down -> down-speed
			if IsPresent(transformed, "down") && !IsPresent(transformed, "down-speed") {
				transformed["down-speed"] = GetString(transformed, "down")
				delete(transformed, "down")
			}

			// up -> up-speed
			if IsPresent(transformed, "up") && !IsPresent(transformed, "up-speed") {
				transformed["up-speed"] = GetString(transformed, "up")
				delete(transformed, "up")
			}

			// Extract numeric values from down-speed and up-speed
			if IsPresent(transformed, "down-speed") {
				downSpeed := fmt.Sprintf("%v", transformed["down-speed"])
				re := regexp.MustCompile(`\d+`)
				if match := re.FindString(downSpeed); match != "" {
					transformed["down-speed"] = match
				} else {
					transformed["down-speed"] = "0"
				}
			}

			if IsPresent(transformed, "up-speed") {
				upSpeed := fmt.Sprintf("%v", transformed["up-speed"])
				re := regexp.MustCompile(`\d+`)
				if match := re.FindString(upSpeed); match != "" {
					transformed["up-speed"] = match
				} else {
					transformed["up-speed"] = "0"
				}
			}
		}

		// Hysteria2 transformations
		if proxyType == "hysteria2" {
			// password -> auth
			if IsPresent(transformed, "password") && !IsPresent(transformed, "auth") {
				transformed["auth"] = GetString(transformed, "password")
				delete(transformed, "password")
			}

			// tfo -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
				delete(transformed, "tfo")
			}

			// down -> down-speed
			if IsPresent(transformed, "down") && !IsPresent(transformed, "down-speed") {
				transformed["down-speed"] = GetString(transformed, "down")
				delete(transformed, "down")
			}

			// up -> up-speed
			if IsPresent(transformed, "up") && !IsPresent(transformed, "up-speed") {
				transformed["up-speed"] = GetString(transformed, "up")
				delete(transformed, "up")
			}

			// Extract numeric values
			if IsPresent(transformed, "down-speed") {
				downSpeed := fmt.Sprintf("%v", transformed["down-speed"])
				re := regexp.MustCompile(`\d+`)
				if match := re.FindString(downSpeed); match != "" {
					transformed["down-speed"] = match
				} else {
					transformed["down-speed"] = "0"
				}
			}

			if IsPresent(transformed, "up-speed") {
				upSpeed := fmt.Sprintf("%v", transformed["up-speed"])
				re := regexp.MustCompile(`\d+`)
				if match := re.FindString(upSpeed); match != "" {
					transformed["up-speed"] = match
				} else {
					transformed["up-speed"] = "0"
				}
			}
		}

		// WireGuard transformations
		if proxyType == "wireguard" {
			keepalive := GetInt(transformed, "keepalive")
			if keepalive == 0 {
				keepalive = GetInt(transformed, "persistent-keepalive")
			}
			transformed["keepalive"] = keepalive
			transformed["persistent-keepalive"] = keepalive

			presharedKey := GetString(transformed, "preshared-key")
			if presharedKey == "" {
				presharedKey = GetString(transformed, "pre-shared-key")
			}
			transformed["preshared-key"] = presharedKey
			transformed["pre-shared-key"] = presharedKey
		}

		// Snell transformations
		if proxyType == "snell" && GetInt(transformed, "version") < 3 {
			delete(transformed, "udp")
		}

		// VLESS transformations
		if proxyType == "vless" {
			// sni -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}
		}

		// Handle HTTP network options for VMess/VLESS
		network = GetString(transformed, "network")
		if (proxyType == "vmess" || proxyType == "vless") && network == "http" {
			if httpOpts := GetMap(transformed, "http-opts"); httpOpts != nil {
				// Ensure path is array
				if IsPresent(transformed, "http-opts", "path") {
					if path, ok := httpOpts["path"].(string); ok {
						httpOpts["path"] = []string{path}
					}
				}

				// Ensure headers.Host is array
				if headers := GetMap(httpOpts, "headers"); headers != nil {
					if IsPresent(transformed, "http-opts", "headers", "Host") {
						if host, ok := headers["Host"].(string); ok {
							headers["Host"] = []string{host}
						}
					}
				}
			}
		}

		// Handle H2 network options (镜像 JS stash.js 第 249-282 行)
		if (proxyType == "vmess" || proxyType == "vless") && network == "h2" {
			if h2Opts := GetMap(transformed, "h2-opts"); h2Opts != nil {
				// path: 数组取第一个元素 (JS 第 253-259 行)
				if IsPresent(transformed, "h2-opts", "path") {
					if pathSlice, ok := h2Opts["path"].([]interface{}); ok && len(pathSlice) > 0 {
						h2Opts["path"] = pathSlice[0]
					}
				}

				// host: 来源优先级 h2-opts.host -> headers.host -> headers.Host,
				// 统一规范化到顶层 h2-opts.host 为数组 (JS 第 260-272 行)
				headers := GetMap(h2Opts, "headers")
				var host interface{}
				if IsPresent(transformed, "h2-opts", "host") {
					host = h2Opts["host"]
				} else if headers != nil && IsPresent(headers, "host") {
					host = headers["host"]
				} else if headers != nil && IsPresent(headers, "Host") {
					host = headers["Host"]
				}
				if IsPresent(transformed, "h2-opts", "host") ||
					(headers != nil && (IsPresent(headers, "host") || IsPresent(headers, "Host"))) {
					if _, ok := host.([]interface{}); ok {
						h2Opts["host"] = host
					} else {
						h2Opts["host"] = []interface{}{host}
					}
				}

				// 清理 headers 中的 host/Host, headers 为空则删除 (JS 第 273-281 行)
				if headers != nil {
					delete(headers, "host")
					delete(headers, "Host")
					if len(headers) == 0 {
						delete(h2Opts, "headers")
					}
				}
			}
		}

		// Handle WebSocket early data (镜像 JS 第 283-290 行 + normalizeWebSocketEarlyDataPath)
		if network == "ws" {
			networkOpts := GetMap(transformed, "ws-opts")
			if networkOpts == nil {
				networkOpts = map[string]interface{}{}
				transformed["ws-opts"] = networkOpts
			}
			if GetString(networkOpts, "path") == "" {
				networkOpts["path"] = "/"
			}
			// 注: ws+v2ray-http-upgrade 节点已在过滤阶段被跳过, 此处仅处理 ed 查询参数.
			stashNormalizeWSEarlyDataPath(networkOpts)
		}

		// Handle plugin-opts TLS
		if pluginOpts := GetMap(transformed, "plugin-opts"); pluginOpts != nil {
			if GetBool(pluginOpts, "tls") && IsPresent(transformed, "skip-cert-verify") {
				pluginOpts["skip-cert-verify"] = GetBool(transformed, "skip-cert-verify")
			}
		}

		// Delete tls for certain types
		if p.shouldDeleteTLS(proxyType) {
			delete(transformed, "tls")
		}

		// tls-fingerprint -> server-cert-fingerprint
		if IsPresent(transformed, "tls-fingerprint") {
			transformed["server-cert-fingerprint"] = GetString(transformed, "tls-fingerprint")
		}
		delete(transformed, "tls-fingerprint")

		// underlying-proxy -> dialer-proxy (JS stash.js 第 318-321 行)
		if IsPresent(transformed, "underlying-proxy") {
			transformed["dialer-proxy"] = transformed["underlying-proxy"]
		}
		delete(transformed, "underlying-proxy")

		// Remove non-boolean tls
		if IsPresent(transformed, "tls") {
			if _, ok := transformed["tls"].(bool); !ok {
				delete(transformed, "tls")
			}
		}

		// test-url -> benchmark-url
		if IsPresent(transformed, "test-url") {
			transformed["benchmark-url"] = GetString(transformed, "test-url")
			delete(transformed, "test-url")
		}

		// test-timeout -> benchmark-timeout
		if IsPresent(transformed, "test-timeout") {
			transformed["benchmark-timeout"] = GetInt(transformed, "test-timeout")
			delete(transformed, "test-timeout")
		}

		// Clean up fields (镜像 JS 第 336-342 行, 含 ip-cidr/ipv6-cidr)
		p.helper.RemoveProxyFields(transformed,
			"subName", "collectionName", "id", "resolved", "no-resolve",
			"ip-cidr", "ipv6-cidr")

		// Remove null and underscore-prefixed fields for non-internal output
		if outputType != "internal" {
			for key := range transformed {
				if transformed[key] == nil || strings.HasPrefix(key, "_") {
					delete(transformed, key)
				}
			}
		}

		// Clean up grpc options
		if network == "grpc" {
			if grpcOpts := GetMap(transformed, "grpc-opts"); grpcOpts != nil {
				delete(grpcOpts, "_grpc-type")
				delete(grpcOpts, "_grpc-authority")
			}
		}

		result = append(result, transformed)
	}

	// Return based on output type
	if outputType == "internal" {
		return result, nil
	}

	// Generate full Stash config
	return p.generateFullConfig(result, opts), nil
}

// 使用预先定义的模板生成stash配置, 因为stash不兼容clash配置
// proxy-groups: #{proxy-groups}
// proxies: #{proxies}
// rules: #{rules}
// script:
//
//	shortcuts:
//	  quic: network == 'udp' and dst_port == 443
//
// dns:
//
//	default-nameserver:
//	  #{default-nameserver}
//	nameserver:
//	  #{nameserver}
//	skip-cert-verify: true
//	fake-ip-filter:
//	  - '+.stun.*.*'
//	  - '+.stun.*.*.*'
//	  - '+.stun.*.*.*.*'
//	  - '+.stun.*.*.*.*.*'
//	  # Google Voices
//	  - 'lens.l.google.com'
//	  # Nintendo Switch
//	  - '*.n.n.srv.nintendo.net'
//
//	  # PlayStation
//	  - '+.stun.playstation.net'
//	  # XBox
//	  - 'xbox.*.*.microsoft.com'
//	  - '*.*.xboxlive.com'
//	  # Microsoft
//	  - '*.msftncsi.com'
//	  - '*.msftconnecttest.com'
//
// log-level: warning
// mode: rule
func (p *StashProducer) generateFullConfig(proxies []Proxy, opts *ProduceOptions) string {
	var sb strings.Builder

	// Get original config fields if available
	var proxyGroups, rules interface{}
	var ruleProviders map[string]interface{}
	var defaultNameserver, nameserver []interface{}
	var nameserverPolicy map[string]interface{}

	if opts != nil && opts.FullConfig != nil {
		proxyGroups = opts.FullConfig["proxy-groups"]
		rules = opts.FullConfig["rules"]

		// Extract rule-providers
		if rp, ok := opts.FullConfig["rule-providers"].(map[string]interface{}); ok {
			ruleProviders = rp
		}

		// Extract DNS settings
		if dns, ok := opts.FullConfig["dns"].(map[string]interface{}); ok {
			if ns, ok := dns["default-nameserver"].([]interface{}); ok {
				defaultNameserver = ns
			}
			if ns, ok := dns["nameserver"].([]interface{}); ok {
				nameserver = ns
			}
			// Stash doesn't support direct-nameserver / proxy-server-nameserver,
			// merge their values into nameserver (deduplicated).
			nameserver = mergeNameservers(nameserver,
				dns["direct-nameserver"],
				dns["proxy-server-nameserver"],
			)
			if nsp, ok := dns["nameserver-policy"].(map[string]interface{}); ok {
				nameserverPolicy = p.expandNameserverPolicy(nsp)
			}
		}
	}

	// Collect RULE-SET names from rules and build rule-providers for Stash
	ruleSetNames := make(map[string]bool)
	if rules != nil {
		if ruleList, ok := rules.([]interface{}); ok {
			for _, rule := range ruleList {
				if ruleStr, ok := rule.(string); ok {
					// Parse RULE-SET,ruleset-name,policy format
					parts := strings.SplitN(ruleStr, ",", 3)
					if len(parts) >= 2 && strings.ToUpper(parts[0]) == "RULE-SET" {
						ruleSetName := strings.TrimSpace(parts[1])
						ruleSetNames[ruleSetName] = true
					}
				}
			}
		}
	}

	// Build final rule-providers map for Stash (convert mrs to yaml format)
	finalRuleProviders := make(map[string]map[string]interface{})
	for name := range ruleSetNames {
		if ruleProviders != nil {
			if existing, ok := ruleProviders[name].(map[string]interface{}); ok {
				// Provider exists, check if it needs conversion from mrs to yaml
				provider := make(map[string]interface{})
				for k, v := range existing {
					provider[k] = v
				}

				// Check format and URL
				format, _ := provider["format"].(string)
				url, _ := provider["url"].(string)

				// Convert mrs format to yaml format
				if format == "mrs" || strings.HasSuffix(url, ".mrs") {
					provider["format"] = "yaml"
					// Replace .mrs extension with .yaml in URL
					if strings.HasSuffix(url, ".mrs") {
						provider["url"] = strings.TrimSuffix(url, ".mrs") + ".yaml"
					}
					// Update path as well
					if path, ok := provider["path"].(string); ok && strings.HasSuffix(path, ".mrs") {
						provider["path"] = strings.TrimSuffix(path, ".mrs") + ".yaml"
					}
				}

				finalRuleProviders[name] = provider
				continue
			}
		}

		// Provider doesn't exist, create a new one with geosite URL
		finalRuleProviders[name] = map[string]interface{}{
			"type":     "http",
			"format":   "yaml",
			"behavior": "domain",
			"url":      "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/" + name + ".yaml",
			"path":     "./ruleset/" + name + ".yaml",
			"interval": 86400,
		}
	}

	// 收集有效节点名 + 代理组名，用于清理 proxy-groups 中的无效引用
	validNames := make(map[string]bool)
	for _, proxy := range proxies {
		if name := GetString(proxy, "name"); name != "" {
			validNames[name] = true
		}
	}
	// 代理组名本身也是合法引用目标
	if proxyGroups != nil {
		if groups, ok := proxyGroups.([]interface{}); ok {
			for _, group := range groups {
				if gm, ok := group.(map[string]interface{}); ok {
					if name, _ := gm["name"].(string); name != "" {
						validNames[name] = true
					}
				}
			}
		}
	}
	// 内置策略名
	for _, builtin := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"} {
		validNames[builtin] = true
	}

	// Write proxy-groups
	sb.WriteString("proxy-groups:\n")
	if proxyGroups != nil {
		if groups, ok := proxyGroups.([]interface{}); ok {
			for _, group := range groups {
				gm, ok := group.(map[string]interface{})
				if !ok {
					groupBytes, _ := json.Marshal(group)
					sb.WriteString("  - ")
					sb.Write(groupBytes)
					sb.WriteString("\n")
					continue
				}
				// 清理 proxies 列表中的无效引用
				if groupProxies, ok := gm["proxies"].([]interface{}); ok {
					cleaned := make([]interface{}, 0, len(groupProxies))
					groupName, _ := gm["name"].(string)
					for _, p := range groupProxies {
						name, _ := p.(string)
						if name == "" || validNames[name] {
							cleaned = append(cleaned, p)
						} else {
							logger.Info("[Stash] 清理 proxy-group 中无效节点引用",
								"group", groupName, "removed_node", name)
						}
					}
					gm["proxies"] = cleaned
				}
				groupBytes, err := json.Marshal(gm)
				if err != nil {
					continue
				}
				sb.WriteString("  - ")
				sb.Write(groupBytes)
				sb.WriteString("\n")
			}
		}
	}

	// Write proxies
	sb.WriteString("proxies:\n")
	for _, proxy := range proxies {
		jsonBytes, err := json.Marshal(proxy)
		if err != nil {
			continue
		}
		sb.WriteString("  - ")
		sb.Write(jsonBytes)
		sb.WriteString("\n")
	}

	// Write rule-providers (if any RULE-SET rules exist)
	if len(finalRuleProviders) > 0 {
		sb.WriteString("rule-providers:\n")
		// Sort keys for consistent output
		sortedNames := make([]string, 0, len(finalRuleProviders))
		for name := range finalRuleProviders {
			sortedNames = append(sortedNames, name)
		}
		// Simple sort
		for i := 0; i < len(sortedNames); i++ {
			for j := i + 1; j < len(sortedNames); j++ {
				if sortedNames[i] > sortedNames[j] {
					sortedNames[i], sortedNames[j] = sortedNames[j], sortedNames[i]
				}
			}
		}
		for _, name := range sortedNames {
			provider := finalRuleProviders[name]
			sb.WriteString("  ")
			sb.WriteString(name)
			sb.WriteString(":\n")
			// Write provider fields in a specific order
			if v, ok := provider["type"]; ok {
				sb.WriteString("    type: ")
				sb.WriteString(fmt.Sprintf("%v", v))
				sb.WriteString("\n")
			}
			if v, ok := provider["format"]; ok {
				sb.WriteString("    format: ")
				sb.WriteString(fmt.Sprintf("%v", v))
				sb.WriteString("\n")
			}
			if v, ok := provider["behavior"]; ok {
				sb.WriteString("    behavior: ")
				sb.WriteString(fmt.Sprintf("%v", v))
				sb.WriteString("\n")
			}
			if v, ok := provider["url"]; ok {
				sb.WriteString("    url: ")
				sb.WriteString(fmt.Sprintf("%v", v))
				sb.WriteString("\n")
			}
			if v, ok := provider["path"]; ok {
				sb.WriteString("    path: ")
				sb.WriteString(fmt.Sprintf("%v", v))
				sb.WriteString("\n")
			}
			if v, ok := provider["interval"]; ok {
				sb.WriteString("    interval: ")
				sb.WriteString(fmt.Sprintf("%v", v))
				sb.WriteString("\n")
			}
		}
	}

	// Write rules
	sb.WriteString("rules:\n")
	if rules != nil {
		if ruleList, ok := rules.([]interface{}); ok {
			for _, rule := range ruleList {
				if ruleStr, ok := rule.(string); ok {
					sb.WriteString("  - ")
					sb.WriteString(ruleStr)
					sb.WriteString("\n")
				}
			}
		}
	}

	// Write script section
	sb.WriteString("script:\n")
	sb.WriteString("  shortcuts:\n")
	sb.WriteString("    quic: network == 'udp' and dst_port == 443\n")

	// Write DNS section
	sb.WriteString("dns:\n")

	// default-nameserver
	sb.WriteString("  default-nameserver:\n")
	if len(defaultNameserver) > 0 {
		for _, ns := range defaultNameserver {
			if nsStr, ok := ns.(string); ok {
				sb.WriteString("    - ")
				sb.WriteString(nsStr)
				sb.WriteString("\n")
			}
		}
	}

	// nameserver
	sb.WriteString("  nameserver:\n")
	if len(nameserver) > 0 {
		for _, ns := range nameserver {
			if nsStr, ok := ns.(string); ok {
				sb.WriteString("    - ")
				sb.WriteString(nsStr)
				sb.WriteString("\n")
			}
		}
	}

	// nameserver-policy (keys sorted for stable output)
	if len(nameserverPolicy) > 0 {
		sb.WriteString("  nameserver-policy:\n")
		sortedKeys := make([]string, 0, len(nameserverPolicy))
		for key := range nameserverPolicy {
			sortedKeys = append(sortedKeys, key)
		}
		for i := 0; i < len(sortedKeys); i++ {
			for j := i + 1; j < len(sortedKeys); j++ {
				if sortedKeys[i] > sortedKeys[j] {
					sortedKeys[i], sortedKeys[j] = sortedKeys[j], sortedKeys[i]
				}
			}
		}
		for _, key := range sortedKeys {
			val := nameserverPolicy[key]
			// stash 文档显示支持多个dns server, 实际上不支持, 先只取第一个
			// sb.WriteString(":\n")
			// if servers, ok := val.([]interface{}); ok {
			// 	for _, s := range servers {
			// 		if sStr, ok := s.(string); ok {
			// 			sb.WriteString("      - ")
			// 			sb.WriteString(sStr)
			// 			sb.WriteString("\n")
			// 		}
			// 	}
			// }
			sb.WriteString("    ")
			sb.WriteString(key)
			sb.WriteString(": ")
			if servers, ok := val.([]interface{}); ok && len(servers) > 0 {
				if sStr, ok := servers[0].(string); ok {
					sb.WriteString(sStr)
				}
			} else if sStr, ok := val.(string); ok {
				sb.WriteString(sStr)
			}
			sb.WriteString("\n")
		}
	}

	// Fixed DNS settings for Stash
	sb.WriteString("  skip-cert-verify: true\n")
	sb.WriteString("  fake-ip-filter:\n")
	sb.WriteString("    - '+.stun.*.*'\n")
	sb.WriteString("    - '+.stun.*.*.*'\n")
	sb.WriteString("    - '+.stun.*.*.*.*'\n")
	sb.WriteString("    - '+.stun.*.*.*.*.*'\n")
	sb.WriteString("    - 'lens.l.google.com'\n")
	sb.WriteString("    - '*.n.n.srv.nintendo.net'\n")
	sb.WriteString("    - '+.stun.playstation.net'\n")
	sb.WriteString("    - 'xbox.*.*.microsoft.com'\n")
	sb.WriteString("    - '*.*.xboxlive.com'\n")
	sb.WriteString("    - '*.msftncsi.com'\n")
	sb.WriteString("    - '*.msftconnecttest.com'\n")

	// Write other fixed settings
	sb.WriteString("log-level: warning\n")
	sb.WriteString("mode: rule\n")

	return sb.String()
}

// mergeNameservers appends values from extra nameserver lists into base, skipping duplicates.
func mergeNameservers(base []interface{}, extras ...interface{}) []interface{} {
	seen := make(map[string]bool, len(base))
	for _, v := range base {
		if s, ok := v.(string); ok {
			seen[s] = true
		}
	}
	for _, extra := range extras {
		if list, ok := extra.([]interface{}); ok {
			for _, v := range list {
				if s, ok := v.(string); ok && !seen[s] {
					seen[s] = true
					base = append(base, v)
				}
			}
		}
	}
	return base
}

// expandNameserverPolicy expands comma-separated geosite keys into individual entries.
// Stash only supports one geosite per key, e.g. "geosite:cn,private" becomes
// two entries: "geosite:cn" and "geosite:private".
func (p *StashProducer) expandNameserverPolicy(policy map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, val := range policy {
		trimmedKey := strings.TrimSpace(key)
		if strings.HasPrefix(trimmedKey, "geosite:") && strings.Contains(trimmedKey, ",") {
			suffix := strings.TrimPrefix(trimmedKey, "geosite:")
			parts := strings.Split(suffix, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					result["geosite:"+part] = val
				}
			}
		} else {
			result[trimmedKey] = val
		}
	}
	return result
}

func (p *StashProducer) isSupportedType(proxyType string) bool {
	supportedTypes := []string{
		"ss", "ssr", "vmess", "socks5", "http", "snell",
		"trojan", "tuic", "vless", "wireguard",
		"hysteria", "hysteria2", "ssh", "juicity", "anytls",
		"tailscale", "trusttunnel",
	}

	for _, t := range supportedTypes {
		if t == proxyType {
			return true
		}
	}
	return false
}

func (p *StashProducer) shouldDeleteTLS(proxyType string) bool {
	deleteTLSTypes := []string{
		"trojan", "tuic", "hysteria", "hysteria2", "juicity", "anytls",
		"trusttunnel", "naive",
	}

	for _, t := range deleteTLSTypes {
		if t == proxyType {
			return true
		}
	}
	return false
}

// stashSupportsSSV2rayPluginMode 镜像 JS supportsShadowsocksV2rayPluginMode:
// 仅当节点是 ss 且 plugin == v2ray-plugin 时才校验 mode; 否则一律支持.
// mode 取自 plugin-opts.mode, 去空格小写后须命中 supportedModes 之一.
func stashSupportsSSV2rayPluginMode(proxy Proxy, supportedModes ...string) bool {
	if GetString(proxy, "type") != "ss" || GetString(proxy, "plugin") != "v2ray-plugin" {
		return true
	}
	pluginOpts := GetMap(proxy, "plugin-opts")
	if pluginOpts == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(GetString(pluginOpts, "mode")))
	for _, m := range supportedModes {
		if m == mode {
			return true
		}
	}
	return false
}

// stashExtractPathQueryParam 镜像 JS extractPathQueryParam:
// 从 path 中移除名为 paramName 的查询参数, 返回剩余 path 与该参数首个非空值.
// 不做 URL 解码(节点 path 通常已是字面值), 仅按 ? 与 & 分割.
func stashExtractPathQueryParam(rawPath, paramName string) (string, string) {
	qi := strings.Index(rawPath, "?")
	if qi == -1 {
		return rawPath, ""
	}
	basePath := rawPath[:qi]
	query := rawPath[qi+1:]
	var kept []string
	value := ""
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		key := part
		val := ""
		if eq := strings.Index(part, "="); eq != -1 {
			key = part[:eq]
			val = part[eq+1:]
		}
		if key == paramName {
			if value == "" && val != "" {
				value = val
			}
			continue
		}
		kept = append(kept, part)
	}
	if len(kept) > 0 {
		return basePath + "?" + strings.Join(kept, "&"), value
	}
	return basePath, value
}

// stashNormalizeWSEarlyDataPath 镜像 JS normalizeWebSocketEarlyDataPath 的非 v2ray-http-upgrade 分支:
// 提取 path 中的整数 ed 参数, 设置 early-data-header-name 与 max-early-data.
func stashNormalizeWSEarlyDataPath(wsOpts map[string]interface{}) {
	if wsOpts == nil {
		return
	}
	rawPath := GetString(wsOpts, "path")
	cleanPath, edStr := stashExtractPathQueryParam(rawPath, "ed")
	// ed 必须是纯数字才视为有效 (镜像 JS parseSafeIntegerValue)
	if edStr == "" || !regexp.MustCompile(`^\d+$`).MatchString(edStr) {
		return
	}
	maxEarlyData := 0
	fmt.Sscanf(edStr, "%d", &maxEarlyData)
	wsOpts["path"] = cleanPath
	if !IsPresent(wsOpts, "early-data-header-name") {
		wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
	}
	if !IsPresent(wsOpts, "max-early-data") {
		wsOpts["max-early-data"] = maxEarlyData
	}
}

// stashNormalizeVmessCipher 镜像 JS normalizeClashVmessSecurity:
// 去空格小写, 别名 chacha20-ietf-poly1305 归一为 chacha20-poly1305,
// 支持集 auto/aes-128-gcm/chacha20-poly1305/none, 空或不支持回退 auto.
func stashNormalizeVmessCipher(cipher string) string {
	normalized := strings.ToLower(strings.TrimSpace(cipher))
	if normalized == "" {
		return "auto"
	}
	if normalized == "chacha20-ietf-poly1305" {
		normalized = "chacha20-poly1305"
	}
	switch normalized {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "none":
		return normalized
	default:
		return "auto"
	}
}
