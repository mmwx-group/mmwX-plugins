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

	supportedVMessCiphers := map[string]bool{
		"auto":              true,
		"aes-128-gcm":       true,
		"chacha20-poly1305": true,
		"none":              true,
	}

	var result []Proxy
	for _, proxy := range proxies {
		proxyType := p.helper.GetProxyType(proxy)

		// Filter unsupported types
		shouldSkip := false

		// Check supported types
		if !p.isSupportedType(proxyType) {
			shouldSkip = true
			logger.Info("[Stash] 跳过不支持的协议类型", "name", GetString(proxy, "name"), "type", proxyType)
		}

		// Check SS cipher
		if proxyType == "ss" {
			cipher := GetString(proxy, "cipher")
			if !supportedSSCiphers[cipher] {
				// 客户端兼容模式开启时跳过不支持的cipher节点
				if opts.ClientCompatibilityMode {
					shouldSkip = true
					logger.Info("[Stash] 跳过不支持的SS加密方式", "name", GetString(proxy, "name"), "cipher", cipher)
				}
			}
		}

		// Check Snell version
		if proxyType == "snell" && GetInt(proxy, "version") >= 4 {
			shouldSkip = true
			logger.Info("[Stash] 跳过Snell v4+节点", "name", GetString(proxy, "name"), "version", GetInt(proxy, "version"))
		}

		// Check VLESS reality
		if proxyType == "vless" && IsPresent(proxy, "reality-opts") {
			flow := GetString(proxy, "flow")
			if flow != "xtls-rprx-vision" {
				// 客户端兼容模式开启时跳过没有流控算法的节点
				if opts.ClientCompatibilityMode {
					shouldSkip = true
					logger.Info("[Stash] 跳过VLESS reality节点(缺少xtls-rprx-vision流控)", "name", GetString(proxy, "name"), "flow", flow)
				}
			}
		}

		// Check underlying-proxy / dialer-proxy
		if IsPresent(proxy, "underlying-proxy") || IsPresent(proxy, "dialer-proxy") {
			// 客户端兼容模式开启时跳过链式代理节点
			if opts.ClientCompatibilityMode {
				shouldSkip = true
				logger.Info("[Stash] 跳过链式代理节点", "name", GetString(proxy, "name"))
			}
		}

		// Check anytls: requires include-unsupported-proxy
		if proxyType == "anytls" && !opts.IncludeUnsupportedProxy {
			shouldSkip = true
			logger.Info("[Stash] 跳过anytls节点(需要启用include-unsupported-proxy)", "name", GetString(proxy, "name"))
		}

		// Check anytls network
		if proxyType == "anytls" {
			network := GetString(proxy, "network")
			if network != "" && network != "tcp" {
				shouldSkip = true
				logger.Info("[Stash] 跳过anytls节点(不支持的network)", "name", GetString(proxy, "name"), "network", network)
			}
			if network == "tcp" && IsPresent(proxy, "reality-opts") {
				shouldSkip = true
				logger.Info("[Stash] 跳过anytls节点(tcp+reality不支持)", "name", GetString(proxy, "name"))
			}
		}

		// Check xhttp network
		if GetString(proxy, "network") == "xhttp" {
			shouldSkip = true
			logger.Info("[Stash] 跳过xhttp网络节点", "name", GetString(proxy, "name"))
		}

		// Check VLESS encryption
		if proxyType == "vless" {
			encryption := GetString(proxy, "encryption")
			if encryption != "" && encryption != "none" {
				shouldSkip = true
				logger.Info("[Stash] 跳过VLESS节点(encryption必须为none)", "name", GetString(proxy, "name"), "encryption", encryption)
			}
		}

		// Check ws + v2ray-http-upgrade
		if GetString(proxy, "network") == "ws" {
			if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
				if GetBool(wsOpts, "v2ray-http-upgrade") {
					shouldSkip = true
					logger.Info("[Stash] 跳过ws+v2ray-http-upgrade节点", "name", GetString(proxy, "name"))
				}
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

			// Cipher validation
			if IsPresent(transformed, "cipher") {
				cipher := GetString(transformed, "cipher")
				if !supportedVMessCiphers[cipher] {
					transformed["cipher"] = "auto"
				}
			}
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
		network := GetString(transformed, "network")
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

		// Handle H2 network options
		if (proxyType == "vmess" || proxyType == "vless") && network == "h2" {
			if h2Opts := GetMap(transformed, "h2-opts"); h2Opts != nil {
				// Ensure path is string (take first element if array)
				if IsPresent(transformed, "h2-opts", "path") {
					if pathSlice, ok := h2Opts["path"].([]interface{}); ok && len(pathSlice) > 0 {
						h2Opts["path"] = pathSlice[0]
					}
				}

				// Ensure host is array
				if headers := GetMap(h2Opts, "headers"); headers != nil {
					if IsPresent(transformed, "h2-opts", "headers", "Host") {
						if host, ok := headers["Host"].(string); ok {
							headers["host"] = []string{host}
						}
					}
				}
			}
		}

		// Handle WebSocket early data
		if network == "ws" {
			networkOpts := GetMap(transformed, "ws-opts")
			if networkOpts != nil {
				if path := GetString(networkOpts, "path"); path != "" {
					re := regexp.MustCompile(`^(.*?)(?:\?ed=(\d+))?$`)
					matches := re.FindStringSubmatch(path)
					if len(matches) > 1 {
						cleanPath := matches[1]
						networkOpts["path"] = cleanPath

						if len(matches) > 2 && matches[2] != "" {
							networkOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
							edValue := 0
							fmt.Sscanf(matches[2], "%d", &edValue)
							networkOpts["max-early-data"] = edValue
						}
					}
				} else {
					networkOpts["path"] = "/"
				}
			} else {
				transformed["ws-opts"] = map[string]interface{}{
					"path": "/",
				}
			}
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

		// Clean up fields
		p.helper.RemoveProxyFields(transformed,
			"subName", "collectionName", "id", "resolved", "no-resolve")

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
	}

	for _, t := range deleteTLSTypes {
		if t == proxyType {
			return true
		}
	}
	return false
}
