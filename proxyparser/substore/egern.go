package substore

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// EgernProducer implements the Producer interface for Egern format
// https://egernapp.com/zh-CN/docs/configuration/proxies
type EgernProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewEgernProducer creates a new Egern producer
func NewEgernProducer() *EgernProducer {
	return &EgernProducer{
		producerType: "egern",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *EgernProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Egern format
func (p *EgernProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	// Supported Shadowsocks ciphers for Egern
	supportedSSCiphers := map[string]bool{
		"chacha20-ietf-poly1305":  true,
		"chacha20-poly1305":       true,
		"aes-256-gcm":             true,
		"aes-128-gcm":             true,
		"none":                    true,
		"tbale":                   true,
		"rc4":                     true,
		"rc4-md5":                 true,
		"aes-128-cfb":             true,
		"aes-192-cfb":             true,
		"aes-256-cfb":             true,
		"aes-128-ctr":             true,
		"aes-192-ctr":             true,
		"aes-256-ctr":             true,
		"bf-cfb":                  true,
		"camellia-128-cfb":        true,
		"camellia-192-cfb":        true,
		"camellia-256-cfb":        true,
		"cast5-cfb":               true,
		"des-cfb":                 true,
		"idea-cfb":                true,
		"rc2-cfb":                 true,
		"seed-cfb":                true,
		"salsa20":                 true,
		"chacha20":                true,
		"chacha20-ietf":           true,
		"2022-blake3-aes-128-gcm": true,
		"2022-blake3-aes-256-gcm": true,
	}

	// Filter and transform proxies
	result := make([]map[string]interface{}, 0)

	for _, proxy := range proxies {
		original := p.helper.CloneProxy(proxy)
		proxyType := p.helper.GetProxyType(proxy)

		// Filter unsupported proxy types
		if !p.isSupportedType(proxyType) {
			continue
		}

		// Check Shadowsocks cipher and plugin
		if proxyType == "ss" {
			cipher := GetString(proxy, "cipher")
			plugin := GetString(proxy, "plugin")

			// Check plugin mode
			if plugin == "obfs" {
				if pluginOpts := GetMap(proxy, "plugin-opts"); pluginOpts != nil {
					mode := GetString(pluginOpts, "mode")
					if mode != "" && mode != "http" && mode != "tls" {
						continue
					}
				}
			}

			// Check cipher
			if !supportedSSCiphers[cipher] {
				continue
			}
		}

		// Check VMess network
		if proxyType == "vmess" {
			network := GetString(proxy, "network")
			if network != "" && network != "http" && network != "ws" && network != "tcp" && network != "grpc" {
				continue
			}
			if !isEgernGrpcGun(proxy) {
				continue
			}
		}

		// Check Trojan network
		if proxyType == "trojan" {
			network := GetString(proxy, "network")
			if network != "" && network != "http" && network != "ws" && network != "tcp" {
				continue
			}
		}

		// Check VLESS network and flow
		if proxyType == "vless" {
			network := GetString(proxy, "network")
			// flow := GetString(proxy, "flow")

			// 已经支持 vless reality 和 xtls-rprx-vision , 不再过滤 flow 与 reality-opts 字段
			// Check flow support
			// if !opts.IncludeUnsupportedProxy {
			// 	if IsPresent(proxy, "flow") || IsPresent(proxy, "reality-opts") {
			// 		continue
			// 	}
			// } else {
			// 	if flow != "" && flow != "xtls-rprx-vision" {
			// 		continue
			// 	}
			// }

			// Check network
			if network != "" && network != "http" && network != "ws" && network != "tcp" && network != "grpc" {
				continue
			}
			if !isEgernGrpcGun(proxy) {
				continue
			}
		}

		// Check TUIC token
		if proxyType == "tuic" {
			token := GetString(proxy, "token")
			if token != "" {
				continue
			}
		}

		// Check Snell version and shadow-tls (Egern 不支持 Snell shadow-tls)
		if proxyType == "snell" {
			if _, _, valid := normalizeSnellVersion(proxy); !valid {
				continue
			}
			if egernHasShadowTls(proxy) {
				continue
			}
		}

		// Check AnyTLS network (Egern 仅支持 tcp)
		if proxyType == "anytls" {
			network := GetString(proxy, "network")
			if network != "" && network != "tcp" {
				continue
			}
		}

		// Check ws + v2ray-http-upgrade
		if GetString(proxy, "network") == "ws" {
			if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
				if GetBool(wsOpts, "v2ray-http-upgrade") {
					continue
				}
			}
		}

		// Set default SNI
		if GetBool(proxy, "tls") && !IsPresent(proxy, "sni") {
			proxy["sni"] = GetString(proxy, "server")
		}

		// Get prev_hop (underlying proxy)
		prevHop := ""
		if IsPresent(original, "prev_hop") {
			prevHop = GetString(original, "prev_hop")
		} else if IsPresent(original, "underlying-proxy") {
			prevHop = GetString(original, "underlying-proxy")
		} else if IsPresent(original, "dialer-proxy") {
			prevHop = GetString(original, "dialer-proxy")
		} else if IsPresent(original, "detour") {
			prevHop = GetString(original, "detour")
		}

		var transformed Proxy
		var flow string

		// Transform based on proxy type
		switch proxyType {
		case "http":
			transformed = p.transformHTTP(proxy, original)
		case "socks5":
			transformed = p.transformSOCKS5(proxy, original)
		case "ss":
			transformed = p.transformShadowsocks(proxy, original)
		case "hysteria2":
			transformed = p.transformHysteria2(proxy, original)
		case "tuic":
			transformed = p.transformTUIC(proxy, original)
		case "trojan":
			transformed = p.transformTrojan(proxy, original)
		case "vmess":
			transformed = p.transformVMess(proxy, original)
		case "vless":
			transformed, flow = p.transformVLess(proxy, original)
		case "wireguard":
			transformed = p.transformWireGuard(proxy, original)
		case "ssh":
			transformed = p.transformSSH(proxy, original)
		case "snell":
			transformed = p.transformSnell(proxy, original)
		case "anytls":
			transformed = p.transformAnyTLS(proxy, original)
		default:
			continue
		}

		// Add flow if present
		if flow != "" {
			transformed["flow"] = flow
		}

		// Handle shadow-tls for supported types
		if p.supportsShadowTLS(GetString(original, "type")) {
			if IsPresent(original, "shadow-tls-password") {
				version := GetInt(original, "shadow-tls-version")
				if version != 3 {
					return nil, fmt.Errorf("shadow-tls version %d is not supported", version)
				}
				transformed["shadow_tls"] = map[string]interface{}{
					"password": GetString(original, "shadow-tls-password"),
					"sni":      GetString(original, "shadow-tls-sni"),
				}
			} else if GetString(original, "plugin") == "shadow-tls" {
				if pluginOpts := GetMap(original, "plugin-opts"); pluginOpts != nil {
					version := GetInt(pluginOpts, "version")
					if version != 3 {
						return nil, fmt.Errorf("shadow-tls version %d is not supported", version)
					}
					transformed["shadow_tls"] = map[string]interface{}{
						"password": GetString(pluginOpts, "password"),
						"sni":      GetString(pluginOpts, "host"),
					}
				}
			}
		}

		// Handle UDP port for Shadowsocks with shadow-tls
		if GetString(original, "type") == "ss" && IsPresent(transformed, "shadow_tls") {
			udpPort := GetInt(original, "udp-port")
			if udpPort > 0 && udpPort <= 65535 {
				transformed["udp_port"] = udpPort
			}
		}

		// Clean up metadata fields
		delete(transformed, "subName")
		delete(transformed, "collectionName")
		delete(transformed, "id")
		delete(transformed, "resolved")
		delete(transformed, "no-resolve")

		// Clean up empty transport objects
		if transport := GetMap(transformed, "transport"); transport != nil {
			for key, val := range transport {
				if subMap, ok := val.(map[string]interface{}); ok {
					isEmpty := true
					for _, v := range subMap {
						if v != nil {
							isEmpty = false
							break
						}
					}
					if isEmpty {
						delete(transport, key)
					}
				}
			}
			if len(transport) == 0 {
				delete(transformed, "transport")
			}
		}

		// Remove null and underscore-prefixed fields for non-internal output
		if outputType != "internal" {
			for key := range transformed {
				if transformed[key] == nil || strings.HasPrefix(key, "_") {
					delete(transformed, key)
				}
			}
		}

		// Build final proxy object with type as key
		proxyObj := map[string]interface{}{
			GetString(transformed, "type"): transformed,
		}

		// Remove type from nested object and add prev_hop
		delete(transformed, "type")
		if prevHop != "" {
			transformed["prev_hop"] = prevHop
		}

		result = append(result, proxyObj)
	}

	// Return based on output type
	if outputType == "internal" {
		return result, nil
	}

	// Generate YAML string with JSON representation
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for _, proxy := range result {
		jsonBytes, err := json.Marshal(proxy)
		if err != nil {
			continue
		}
		sb.WriteString("  - ")
		sb.Write(jsonBytes)
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// isSupportedType checks if a proxy type is supported by Egern
func (p *EgernProducer) isSupportedType(proxyType string) bool {
	supportedTypes := []string{
		"http", "socks5", "ss", "trojan", "hysteria2", "vless", "vmess", "tuic",
		"wireguard", "anytls", "ssh", "snell",
	}
	for _, t := range supportedTypes {
		if t == proxyType {
			return true
		}
	}
	return false
}

// supportsShadowTLS checks if a proxy type supports shadow-tls
func (p *EgernProducer) supportsShadowTLS(proxyType string) bool {
	supportedTypes := []string{
		"http", "socks5", "ss", "trojan", "vless", "vmess", "anytls", "ssh",
	}
	for _, t := range supportedTypes {
		if t == proxyType {
			return true
		}
	}
	return false
}

// transformHTTP transforms HTTP proxy
func (p *EgernProducer) transformHTTP(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "http"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "username") {
		result["username"] = GetString(proxy, "username")
	}
	if IsPresent(proxy, "password") {
		result["password"] = GetString(proxy, "password")
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	return result
}

// transformSOCKS5 transforms SOCKS5 proxy
func (p *EgernProducer) transformSOCKS5(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "socks5"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "username") {
		result["username"] = GetString(proxy, "username")
	}
	if IsPresent(proxy, "password") {
		result["password"] = GetString(proxy, "password")
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	return result
}

// transformShadowsocks transforms Shadowsocks proxy
func (p *EgernProducer) transformShadowsocks(proxy, original Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "shadowsocks"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")
	result["password"] = GetString(proxy, "password")

	// Handle cipher conversion
	cipher := GetString(proxy, "cipher")
	if cipher == "chacha20-ietf-poly1305" {
		result["method"] = "chacha20-poly1305"
	} else {
		result["method"] = cipher
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	// Handle obfs plugin
	if GetString(original, "plugin") == "obfs" {
		if pluginOpts := GetMap(original, "plugin-opts"); pluginOpts != nil {
			if IsPresent(pluginOpts, "mode") {
				result["obfs"] = GetString(pluginOpts, "mode")
			}
			if IsPresent(pluginOpts, "host") {
				result["obfs_host"] = GetString(pluginOpts, "host")
			}
			if IsPresent(pluginOpts, "path") {
				result["obfs_uri"] = GetString(pluginOpts, "path")
			}
		}
	}

	return result
}

// transformHysteria2 transforms Hysteria2 proxy
func (p *EgernProducer) transformHysteria2(proxy, original Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "hysteria2"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "password") {
		result["auth"] = GetString(proxy, "password")
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	if IsPresent(proxy, "servername") {
		result["sni"] = GetString(proxy, "servername")
	}

	if IsPresent(proxy, "skip-cert-verify") {
		result["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
	}

	if IsPresent(proxy, "ports") {
		result["port_hopping"] = GetString(proxy, "ports")
	}

	if IsPresent(proxy, "hop-interval") {
		result["port_hopping_interval"] = GetString(proxy, "hop-interval")
	}

	// bandwidth：从 up 提取数字（对齐 Sub-Store egern）
	if IsPresent(proxy, "up") {
		n := 0
		if m := regexp.MustCompile(`\d+`).FindString(GetString(proxy, "up")); m != "" {
			n, _ = strconv.Atoi(m)
		}
		result["bandwidth"] = n
	}

	// Handle obfs
	if IsPresent(original, "obfs-password") && GetString(original, "obfs") == "salamander" {
		result["obfs"] = "salamander"
		result["obfs_password"] = GetString(original, "obfs-password")
	}

	return result
}

// transformTUIC transforms TUIC proxy
func (p *EgernProducer) transformTUIC(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "tuic"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "uuid") {
		result["uuid"] = GetString(proxy, "uuid")
	}
	if IsPresent(proxy, "password") {
		result["password"] = GetString(proxy, "password")
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	if IsPresent(proxy, "servername") {
		result["sni"] = GetString(proxy, "servername")
	}

	// Handle alpn
	if IsPresent(proxy, "alpn") {
		alpnVal := proxy["alpn"]
		if alpnSlice, ok := alpnVal.([]interface{}); ok {
			result["alpn"] = alpnSlice
		} else if alpnStr, ok := alpnVal.(string); ok {
			result["alpn"] = []string{alpnStr}
		} else {
			result["alpn"] = []string{"h3"}
		}
	} else {
		result["alpn"] = []string{"h3"}
	}

	if IsPresent(proxy, "skip-cert-verify") {
		result["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
	}

	if IsPresent(proxy, "ports") {
		result["port_hopping"] = GetString(proxy, "ports")
	}

	if IsPresent(proxy, "hop-interval") {
		result["port_hopping_interval"] = GetString(proxy, "hop-interval")
	}

	return result
}

// transformTrojan transforms Trojan proxy
func (p *EgernProducer) transformTrojan(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "trojan"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")
	result["password"] = GetString(proxy, "password")

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	if IsPresent(proxy, "servername") {
		result["sni"] = GetString(proxy, "servername")
	}

	if IsPresent(proxy, "skip-cert-verify") {
		result["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
	}

	// Handle WebSocket
	if GetString(proxy, "network") == "ws" {
		websocket := make(map[string]interface{})
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if IsPresent(wsOpts, "path") {
				websocket["path"] = GetString(wsOpts, "path")
			}
			if headers := GetMap(wsOpts, "headers"); headers != nil {
				if IsPresent(headers, "Host") {
					websocket["host"] = GetString(headers, "Host")
				}
			}
		}
		if len(websocket) > 0 {
			result["websocket"] = websocket
		}
	}

	return result
}

// transformVMess transforms VMess proxy
func (p *EgernProducer) transformVMess(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "vmess"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")
	result["user_id"] = GetString(proxy, "uuid")

	// Handle security/cipher
	security := GetString(proxy, "cipher")
	validSecurities := map[string]bool{
		"auto": true, "none": true, "zero": true,
		"aes-128-gcm": true, "chacha20-poly1305": true,
	}
	if !validSecurities[security] {
		security = "auto"
	}
	if security != "" {
		result["security"] = security
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	// Handle legacy mode
	var legacy bool
	if IsPresent(proxy, "aead") && !GetBool(proxy, "aead") {
		legacy = true
	} else if GetInt(proxy, "alterId") != 0 {
		legacy = true
	}
	if legacy {
		result["legacy"] = legacy
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	// Handle transport based on network type
	network := GetString(proxy, "network")
	transport := p.buildVMessTransport(proxy, network)
	if transport != nil {
		result["transport"] = transport
	}

	return result
}

// buildVMessTransport builds transport configuration for VMess
func (p *EgernProducer) buildVMessTransport(proxy Proxy, network string) map[string]interface{} {
	tls := GetBool(proxy, "tls")

	switch network {
	case "ws":
		transportKey := "ws"
		if tls {
			transportKey = "wss"
		}

		wsConfig := make(map[string]interface{})
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if IsPresent(wsOpts, "path") {
				wsConfig["path"] = GetString(wsOpts, "path")
			}
			if headers := GetMap(wsOpts, "headers"); headers != nil {
				headerMap := make(map[string]interface{})
				if IsPresent(headers, "Host") {
					headerMap["Host"] = GetString(headers, "Host")
				}
				if len(headerMap) > 0 {
					wsConfig["headers"] = headerMap
				}
			}
		}
		if tls {
			if IsPresent(proxy, "servername") {
				wsConfig["sni"] = GetString(proxy, "servername")
			}
			if IsPresent(proxy, "skip-cert-verify") {
				wsConfig["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
			}
		}
		return map[string]interface{}{transportKey: wsConfig}

	case "http":
		httpConfig := make(map[string]interface{})
		if httpOpts := GetMap(proxy, "http-opts"); httpOpts != nil {
			if IsPresent(httpOpts, "method") {
				httpConfig["method"] = GetString(httpOpts, "method")
			}
			if IsPresent(httpOpts, "path") {
				pathVal := httpOpts["path"]
				if pathSlice, ok := pathVal.([]interface{}); ok && len(pathSlice) > 0 {
					httpConfig["path"] = pathSlice[0]
				} else {
					httpConfig["path"] = pathVal
				}
			}
			if headers := GetMap(httpOpts, "headers"); headers != nil {
				headerMap := make(map[string]interface{})
				if IsPresent(headers, "Host") {
					hostVal := headers["Host"]
					if hostSlice, ok := hostVal.([]interface{}); ok && len(hostSlice) > 0 {
						headerMap["Host"] = hostSlice[0]
					} else {
						headerMap["Host"] = hostVal
					}
				}
				if len(headerMap) > 0 {
					httpConfig["headers"] = headerMap
				}
			}
		}
		if IsPresent(proxy, "skip-cert-verify") {
			httpConfig["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
		}
		return map[string]interface{}{"http1": httpConfig}

	case "h2":
		h2Config := make(map[string]interface{})
		if h2Opts := GetMap(proxy, "h2-opts"); h2Opts != nil {
			if IsPresent(h2Opts, "method") {
				h2Config["method"] = GetString(h2Opts, "method")
			}
			if IsPresent(h2Opts, "path") {
				pathVal := h2Opts["path"]
				if pathSlice, ok := pathVal.([]interface{}); ok && len(pathSlice) > 0 {
					h2Config["path"] = pathSlice[0]
				} else {
					h2Config["path"] = pathVal
				}
			}
			if headers := GetMap(h2Opts, "headers"); headers != nil {
				headerMap := make(map[string]interface{})
				if IsPresent(headers, "Host") {
					hostVal := headers["Host"]
					if hostSlice, ok := hostVal.([]interface{}); ok && len(hostSlice) > 0 {
						headerMap["Host"] = hostSlice[0]
					} else {
						headerMap["Host"] = hostVal
					}
				}
				if len(headerMap) > 0 {
					h2Config["headers"] = headerMap
				}
			}
		}
		if IsPresent(proxy, "skip-cert-verify") {
			h2Config["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
		}
		return map[string]interface{}{"http2": h2Config}

	case "grpc":
		return egernGrpcTransport(proxy)

	case "tcp", "":
		if tls {
			tlsConfig := make(map[string]interface{})
			if IsPresent(proxy, "servername") {
				tlsConfig["sni"] = GetString(proxy, "servername")
			}
			if IsPresent(proxy, "skip-cert-verify") {
				tlsConfig["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
			}
			return map[string]interface{}{"tls": tlsConfig}
		}
	}

	return nil
}

// transformVLess transforms VLESS proxy
func (p *EgernProducer) transformVLess(proxy, _ Proxy) (Proxy, string) {
	result := make(Proxy)
	result["type"] = "vless"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")
	result["user_id"] = GetString(proxy, "uuid")

	if IsPresent(proxy, "cipher") {
		result["security"] = GetString(proxy, "cipher")
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "next_hop") {
		result["next_hop"] = GetString(proxy, "next_hop")
	}

	// Handle transport based on network type
	network := GetString(proxy, "network")
	flow := ""
	transport := p.buildVLessTransport(proxy, network, &flow)
	if transport != nil {
		result["transport"] = transport
	}

	return result, flow
}

// buildVLessTransport builds transport configuration for VLESS
func (p *EgernProducer) buildVLessTransport(proxy Proxy, network string, flow *string) map[string]interface{} {
	tls := GetBool(proxy, "tls")

	switch network {
	case "ws":
		transportKey := "ws"
		if tls {
			transportKey = "wss"
		}

		wsConfig := make(map[string]interface{})
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if IsPresent(wsOpts, "path") {
				wsConfig["path"] = GetString(wsOpts, "path")
			}
			if headers := GetMap(wsOpts, "headers"); headers != nil {
				headerMap := make(map[string]interface{})
				if IsPresent(headers, "Host") {
					headerMap["Host"] = GetString(headers, "Host")
				}
				if len(headerMap) > 0 {
					wsConfig["headers"] = headerMap
				}
			}
		}
		if tls {
			if IsPresent(proxy, "servername") {
				wsConfig["sni"] = GetString(proxy, "servername")
			}
			if IsPresent(proxy, "skip-cert-verify") {
				wsConfig["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
			}
		}
		return map[string]interface{}{transportKey: wsConfig}

	case "http":
		httpConfig := make(map[string]interface{})
		if httpOpts := GetMap(proxy, "http-opts"); httpOpts != nil {
			if IsPresent(httpOpts, "method") {
				httpConfig["method"] = GetString(httpOpts, "method")
			}
			if IsPresent(httpOpts, "path") {
				pathVal := httpOpts["path"]
				if pathSlice, ok := pathVal.([]interface{}); ok && len(pathSlice) > 0 {
					httpConfig["path"] = pathSlice[0]
				} else {
					httpConfig["path"] = pathVal
				}
			}
			if headers := GetMap(httpOpts, "headers"); headers != nil {
				headerMap := make(map[string]interface{})
				if IsPresent(headers, "Host") {
					hostVal := headers["Host"]
					if hostSlice, ok := hostVal.([]interface{}); ok && len(hostSlice) > 0 {
						headerMap["Host"] = hostSlice[0]
					} else {
						headerMap["Host"] = hostVal
					}
				}
				if len(headerMap) > 0 {
					httpConfig["headers"] = headerMap
				}
			}
		}
		if IsPresent(proxy, "skip-cert-verify") {
			httpConfig["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
		}
		return map[string]interface{}{"http": httpConfig}

	case "grpc":
		return egernGrpcTransport(proxy)

	case "tcp", "":
		transportKey := "tcp"
		if tls {
			transportKey = "tls"
		}

		tcpConfig := make(map[string]interface{})
		if tls {
			if IsPresent(proxy, "servername") {
				tcpConfig["sni"] = GetString(proxy, "servername")
			}
			if IsPresent(proxy, "skip-cert-verify") {
				tcpConfig["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
			}

			// Handle reality
			if realityOpts := GetMap(proxy, "reality-opts"); realityOpts != nil {
				if IsPresent(realityOpts, "short-id") || IsPresent(realityOpts, "public-key") {
					reality := make(map[string]interface{})
					if IsPresent(realityOpts, "short-id") {
						reality["short_id"] = GetString(realityOpts, "short-id")
					}
					if IsPresent(realityOpts, "public-key") {
						reality["public_key"] = GetString(realityOpts, "public-key")
					}
					tcpConfig["reality"] = reality
				}
			}
		}

		// Get flow for VLESS
		if flow != nil && IsPresent(proxy, "flow") {
			*flow = GetString(proxy, "flow")
		}

		return map[string]interface{}{transportKey: tcpConfig}
	}

	return nil
}

// egernGrpcTransport builds gRPC transport config (对齐 egern.js getGrpcTransport)
func egernGrpcTransport(proxy Proxy) map[string]interface{} {
	grpc := make(map[string]interface{})
	if grpcOpts := GetMap(proxy, "grpc-opts"); grpcOpts != nil {
		if IsPresent(grpcOpts, "grpc-service-name") {
			grpc["service_name"] = GetString(grpcOpts, "grpc-service-name")
		}
	}
	if IsPresent(proxy, "sni") {
		grpc["sni"] = GetString(proxy, "sni")
	}
	if reality := egernReality(proxy); reality != nil {
		grpc["reality"] = reality
	}
	if IsPresent(proxy, "skip-cert-verify") {
		grpc["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
	}
	return map[string]interface{}{"grpc": grpc}
}

// egernReality builds reality config, 仅在 public-key / short-id 非空时写入 (对齐 getReality)
func egernReality(proxy Proxy) map[string]interface{} {
	realityOpts := GetMap(proxy, "reality-opts")
	if realityOpts == nil {
		return nil
	}
	reality := make(map[string]interface{})
	if pk := GetString(realityOpts, "public-key"); pk != "" {
		reality["public_key"] = pk
	}
	if sid := GetString(realityOpts, "short-id"); sid != "" {
		reality["short_id"] = sid
	}
	if len(reality) == 0 {
		return nil
	}
	return reality
}

// isEgernGrpcGun 仅放行 gun 模式的 gRPC (Egern 不支持 multi 模式)
func isEgernGrpcGun(proxy Proxy) bool {
	if GetString(proxy, "network") != "grpc" {
		return true
	}
	grpcOpts := GetMap(proxy, "grpc-opts")
	if grpcOpts == nil {
		return true
	}
	if !IsPresent(grpcOpts, "_grpc-type") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(GetAnyString(grpcOpts, "_grpc-type")), "gun")
}

// normalizeSnellVersion 返回 (版本号, 是否提供, 是否合法)。version 缺省视为合法且不写入字段；
// 非 1-5 视为非法（过滤）。
func normalizeSnellVersion(proxy Proxy) (int, bool, bool) {
	if !IsPresent(proxy, "version") {
		return 0, false, true
	}
	s := strings.TrimSpace(GetAnyString(proxy, "version"))
	if len(s) != 1 || s[0] < '1' || s[0] > '5' {
		return 0, false, false
	}
	return int(s[0] - '0'), true, true
}

// egernHasShadowTls 判断节点是否带 shadow-tls (Egern 的 Snell 不支持)
func egernHasShadowTls(proxy Proxy) bool {
	return GetString(proxy, "plugin") == "shadow-tls" ||
		IsPresent(proxy, "shadow-tls-password") ||
		IsPresent(proxy, "shadow-tls-sni") ||
		IsPresent(proxy, "shadow-tls-version")
}

// isAllDigits 判断字符串去空格后是否全为数字且非空
func isAllDigits(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseWGCIDR 解析并校验 CIDR (0..max)，无效返回 -1
func parseWGCIDR(s string, max int) int {
	s = strings.TrimSpace(s)
	if !isAllDigits(s) {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > max {
		return -1
	}
	return n
}

// getWireGuardAddressWithCIDR 提取 WireGuard 接口地址并补全 CIDR，对齐 utils.js 同名函数
func getWireGuardAddressWithCIDR(proxy Proxy, family string) string {
	addressKey, cidrKey, defaultCIDR, maxCIDR := "ip", "ip-cidr", 32, 32
	if family == "ipv6" {
		addressKey, cidrKey, defaultCIDR, maxCIDR = "ipv6", "ipv6-cidr", 128, 128
	}

	raw := strings.TrimSpace(GetAnyString(proxy, addressKey))
	if raw == "" {
		return ""
	}

	host := raw
	embedded := -1
	if i := strings.LastIndex(raw, "/"); i >= 0 && isAllDigits(raw[i+1:]) {
		host = strings.TrimSpace(raw[:i])
		embedded = parseWGCIDR(raw[i+1:], maxCIDR)
	}
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	valid := IsIPv4(host)
	if family == "ipv6" {
		valid = IsIPv6(host)
	}
	if !valid {
		return ""
	}

	cidr := parseWGCIDR(GetAnyString(proxy, cidrKey), maxCIDR)
	final := defaultCIDR
	if cidr >= 0 {
		final = cidr
	} else if embedded >= 0 {
		final = embedded
	}
	return host + "/" + strconv.Itoa(final)
}

// splitTrim 按 sep 切分并去除空白与空项
func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// transformWireGuard transforms WireGuard proxy
func (p *EgernProducer) transformWireGuard(proxy, _ Proxy) Proxy {
	// peers[0] 覆盖顶层字段 (对齐 egern.js)。
	// 有意偏离:仅当 peer 实际含该字段时才覆盖。Clash-meta 的 wireguard 接口地址
	// (ip/ipv6) 在顶层、peers 不携带,egern.js 无条件覆盖会把顶层地址抹成 nil 导致
	// 节点地址丢失;miaomiaowu 不预扁平化 peers,故此处保留顶层字段。
	if peers, ok := proxy["peers"].([]interface{}); ok && len(peers) > 0 {
		if peer, ok := peers[0].(map[string]interface{}); ok {
			for _, k := range []string{"server", "port", "ip", "ipv6", "public-key", "pre-shared-key", "allowed-ips", "reserved"} {
				if v, exists := peer[k]; exists && v != nil {
					proxy[k] = v
				}
			}
		}
	}

	result := make(Proxy)
	result["type"] = "wireguard"
	result["name"] = GetString(proxy, "name")
	if v := getWireGuardAddressWithCIDR(proxy, "ipv4"); v != "" {
		result["local_ipv4"] = v
	}
	if v := getWireGuardAddressWithCIDR(proxy, "ipv6"); v != "" {
		result["local_ipv6"] = v
	}
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "private-key") {
		result["private_key"] = GetString(proxy, "private-key")
	}
	if IsPresent(proxy, "public-key") {
		result["peer_public_key"] = GetString(proxy, "public-key")
	}
	// preshared:兼容 preshared-key 与 Clash-meta 的 pre-shared-key 两种写法
	if psk := GetString(proxy, "preshared-key"); psk != "" {
		result["preshared_key"] = psk
	} else if psk := GetString(proxy, "pre-shared-key"); psk != "" {
		result["preshared_key"] = psk
	}

	if IsPresent(proxy, "reserved") {
		switch r := proxy["reserved"].(type) {
		case []interface{}:
			result["reserved"] = r
		case string:
			if parts := splitTrim(r, "/"); len(parts) > 0 {
				result["reserved"] = parts
			}
		}
	}

	if IsPresent(proxy, "dns") {
		switch d := proxy["dns"].(type) {
		case []interface{}:
			result["dns_servers"] = d
		case string:
			if parts := splitTrim(d, ","); len(parts) > 0 {
				result["dns_servers"] = parts
			}
		}
	}

	if IsPresent(proxy, "mtu") {
		result["mtu"] = GetInt(proxy, "mtu")
	}
	// keepalive:兼容 Clash-meta 的 persistent-keepalive 写法
	if IsPresent(proxy, "keepalive") {
		result["keepalive"] = GetInt(proxy, "keepalive")
	} else if IsPresent(proxy, "persistent-keepalive") {
		result["keepalive"] = GetInt(proxy, "persistent-keepalive")
	}

	return result
}

// transformSSH transforms SSH proxy
func (p *EgernProducer) transformSSH(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "ssh"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "username") {
		result["username"] = GetString(proxy, "username")
	}
	if IsPresent(proxy, "password") {
		result["password"] = GetString(proxy, "password")
	}
	if IsPresent(proxy, "private-key") {
		result["private_key"] = GetString(proxy, "private-key")
	}
	if IsPresent(proxy, "host-key") {
		result["host_keys"] = proxy["host-key"]
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	return result
}

// transformSnell transforms Snell proxy
func (p *EgernProducer) transformSnell(proxy, _ Proxy) Proxy {
	version, hasVersion, _ := normalizeSnellVersion(proxy)

	result := make(Proxy)
	result["type"] = "snell"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "psk") {
		result["psk"] = GetString(proxy, "psk")
	}
	if hasVersion {
		result["version"] = version
	}

	// version 缺省或 >=3 时支持 udp_relay
	if !hasVersion || version >= 3 {
		udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
		if udpRelay {
			result["udp_relay"] = udpRelay
		}
	}

	if IsPresent(proxy, "reuse") {
		result["reuse"] = GetBool(proxy, "reuse")
	}

	// obfs: obfs-opts.mode || obfs
	obfs := ""
	if obfsOpts := GetMap(proxy, "obfs-opts"); obfsOpts != nil {
		obfs = GetString(obfsOpts, "mode")
	}
	if obfs == "" {
		obfs = GetString(proxy, "obfs")
	}
	if obfs != "" {
		result["obfs"] = obfs
	}

	// obfs_host: obfs-opts.host || obfs-host || obfs_host
	obfsHost := ""
	if obfsOpts := GetMap(proxy, "obfs-opts"); obfsOpts != nil {
		obfsHost = GetString(obfsOpts, "host")
	}
	if obfsHost == "" {
		obfsHost = GetString(proxy, "obfs-host")
	}
	if obfsHost == "" {
		obfsHost = GetString(proxy, "obfs_host")
	}
	if obfsHost != "" {
		result["obfs_host"] = obfsHost
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	return result
}

// transformAnyTLS transforms AnyTLS proxy
func (p *EgernProducer) transformAnyTLS(proxy, _ Proxy) Proxy {
	result := make(Proxy)
	result["type"] = "anytls"
	result["name"] = GetString(proxy, "name")
	result["server"] = GetString(proxy, "server")
	result["port"] = GetInt(proxy, "port")

	if IsPresent(proxy, "password") {
		result["password"] = GetString(proxy, "password")
	}

	tfo := GetBool(proxy, "tfo") || GetBool(proxy, "fast-open")
	if tfo {
		result["tfo"] = tfo
	}

	udpRelay := GetBool(proxy, "udp") || GetBool(proxy, "udp_relay")
	if udpRelay {
		result["udp_relay"] = udpRelay
	}

	if IsPresent(proxy, "sni") {
		result["sni"] = GetString(proxy, "sni")
	}
	if IsPresent(proxy, "skip-cert-verify") {
		result["skip_tls_verify"] = GetBool(proxy, "skip-cert-verify")
	}
	if reality := egernReality(proxy); reality != nil {
		result["reality"] = reality
	}

	return result
}
