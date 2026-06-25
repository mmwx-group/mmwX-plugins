package substore

import (
	"encoding/json"
	"strings"
)

// srVmessSecurityCommon 对齐 JS vmess-security.js VMESS_SECURITY_COMMON_VALUES
var srVmessSecurityCommon = map[string]bool{
	"auto":              true,
	"none":              true,
	"zero":              true,
	"aes-128-gcm":       true,
	"chacha20-poly1305": true,
}

// srVmessSecurityAliases 对齐 JS VMESS_SECURITY_ALIASES
var srVmessSecurityAliases = map[string]string{
	"chacha20-ietf-poly1305": "chacha20-poly1305",
}

// srNormalizeVmessSecurity 对齐 JS normalizeVmessSecurity(security)(默认 COMMON_VALUES, acceptAliases=true, fallback="auto")。
// 无条件归一化:空值/不支持值均回退到 "auto"。
func srNormalizeVmessSecurity(security string) string {
	normalized := strings.ToLower(strings.TrimSpace(security))
	if normalized == "" {
		return "auto"
	}
	if srVmessSecurityCommon[normalized] {
		if canonical, ok := srVmessSecurityAliases[normalized]; ok {
			return canonical
		}
		return normalized
	}
	// 别名归一后再次匹配受支持集合
	if canonical, ok := srVmessSecurityAliases[normalized]; ok {
		if srVmessSecurityCommon[canonical] {
			return canonical
		}
	}
	return "auto"
}

// srSupportsV2rayPluginMode 对齐 JS supportsShadowsocksV2rayPluginMode:
// 仅当 ss + plugin=v2ray-plugin 时校验 plugin-opts.mode 是否在受支持列表内;其它情况一律 true。
func srSupportsV2rayPluginMode(proxy Proxy, supportedModes map[string]bool) bool {
	if GetString(proxy, "type") != "ss" || GetString(proxy, "plugin") != "v2ray-plugin" {
		return true
	}
	mode := ""
	if pluginOpts := GetMap(proxy, "plugin-opts"); pluginOpts != nil {
		mode = strings.ToLower(strings.TrimSpace(GetString(pluginOpts, "mode")))
	}
	return supportedModes[mode]
}

// srIsShadowsocksOverTls 对齐 JS isShadowsocksOverTls:
// ss + tls===true + 无 plugin + (无 network 或 network=tcp)。
func srIsShadowsocksOverTls(proxy Proxy) bool {
	if GetString(proxy, "type") != "ss" {
		return false
	}
	if tls, ok := proxy["tls"].(bool); !ok || !tls {
		return false
	}
	if IsPresent(proxy, "plugin") {
		return false
	}
	if !IsPresent(proxy, "network") {
		return true
	}
	return strings.ToLower(strings.TrimSpace(GetString(proxy, "network"))) == "tcp"
}

// ShadowrocketProducer implements Shadowrocket format converter
type ShadowrocketProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewShadowrocketProducer creates a new Shadowrocket producer
func NewShadowrocketProducer() *ShadowrocketProducer {
	return &ShadowrocketProducer{
		producerType: "shadowrocket",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *ShadowrocketProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Shadowrocket format
func (p *ShadowrocketProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	// 对齐 JS supportsShadowsocksV2rayPluginMode 的受支持 v2ray-plugin mode 列表
	ssV2rayPluginModes := map[string]bool{
		"websocket": true, "quic": true, "http2": true, "mkcp": true, "grpc": true,
	}

	// Filter and transform proxies
	var result []Proxy
	for _, proxy := range proxies {
		proxyType := p.helper.GetProxyType(proxy)

		// Filter unsupported types(对齐 JS shadowrocket.js filter)
		if !opts.IncludeUnsupportedProxy {
			// ss + v2ray-plugin 但 mode 不受支持
			if !srSupportsV2rayPluginMode(proxy, ssV2rayPluginModes) {
				continue
			}
			// snell 仅支持 version 1..5
			if proxyType == "snell" {
				version := GetInt(proxy, "version")
				if version < 1 || version > 5 {
					continue
				}
			}
			// 明确不支持的类型
			if proxyType == "tailscale" || proxyType == "sudoku" || proxyType == "naive" ||
				proxyType == "openvpn" || proxyType == "gost-relay" {
				continue
			}
			// JS: network==='xhttp' 仅告警保留(VLESS XHTTP 结构复杂, Shadowrocket 可能无法完全兼容)
			// 这里不再额外过滤,落到下方 xhttp/splithttp 纠正性转换处理。
		}

		transformed := p.helper.CloneProxy(proxy)

		// VMess specific transformations
		if proxyType == "vmess" {
			// Handle aead
			if IsPresent(transformed, "aead") {
				if GetBool(transformed, "aead") {
					transformed["alterId"] = 0
				}
				delete(transformed, "aead")
			}

			// SNI -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}

			// Cipher 归一化
			// JS: proxy.cipher = normalizeVmessSecurity(proxy.cipher) —— 无条件赋值,
			// 即使 cipher 缺失也会归一化为 fallback "auto",并处理 chacha20-ietf-poly1305 别名。
			transformed["cipher"] = srNormalizeVmessSecurity(GetString(transformed, "cipher"))
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
			}

			// TFO -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
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

			// TFO -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
			}
		}

		// Hysteria2 transformations
		if proxyType == "hysteria2" {
			// Ensure alpn is array
			if IsPresent(transformed, "alpn") {
				alpnVal := transformed["alpn"]
				if alpnSlice, ok := alpnVal.([]interface{}); ok {
					transformed["alpn"] = alpnSlice
				} else if alpnStr, ok := alpnVal.(string); ok {
					transformed["alpn"] = []string{alpnStr}
				}
			}

			// TFO -> fast-open
			if IsPresent(transformed, "tfo") && !IsPresent(transformed, "fast-open") {
				transformed["fast-open"] = GetBool(transformed, "tfo")
			}
		}

		// WireGuard transformations
		if proxyType == "wireguard" {
			// Keepalive
			if !IsPresent(transformed, "keepalive") && IsPresent(transformed, "persistent-keepalive") {
				transformed["keepalive"] = GetInt(transformed, "persistent-keepalive")
			}
			transformed["persistent-keepalive"] = GetInt(transformed, "keepalive")

			// Preshared key
			if !IsPresent(transformed, "preshared-key") && IsPresent(transformed, "pre-shared-key") {
				transformed["preshared-key"] = GetString(transformed, "pre-shared-key")
			}
			transformed["pre-shared-key"] = GetString(transformed, "preshared-key")

			// JS: proxy.ip / proxy.ipv6 = getWireGuardAddressWithCIDR(...)。
			// 纠正性偏离:Go helper 对无效地址返回空串,而 JS 返回 undefined(随后被 null 清理删除)。
			// 这里地址无效时置为 nil,使下方 null 清理一致删除该键。
			if ip := getWireGuardAddressWithCIDR(transformed, "ipv4"); ip != "" {
				transformed["ip"] = ip
			} else {
				transformed["ip"] = nil
			}
			if ipv6 := getWireGuardAddressWithCIDR(transformed, "ipv6"); ipv6 != "" {
				transformed["ipv6"] = ipv6
			} else {
				transformed["ipv6"] = nil
			}
		}

		// Snell transformations
		if proxyType == "snell" {
			version := GetInt(transformed, "version")
			if version < 3 {
				delete(transformed, "udp")
			}
		}

		// VLESS transformations
		if proxyType == "vless" {
			// SNI -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}
		}

		// SS shadow-tls transformations
		if proxyType == "ss" {
			if IsPresent(transformed, "shadow-tls-password") && !IsPresent(transformed, "plugin") {
				transformed["plugin"] = "shadow-tls"
				pluginOpts := make(map[string]interface{})
				pluginOpts["host"] = GetString(transformed, "shadow-tls-sni")
				pluginOpts["password"] = GetString(transformed, "shadow-tls-password")
				pluginOpts["version"] = GetInt(transformed, "shadow-tls-version")
				transformed["plugin-opts"] = pluginOpts

				delete(transformed, "shadow-tls-password")
				delete(transformed, "shadow-tls-sni")
				delete(transformed, "shadow-tls-version")
			}

			// Shadowsocks over TLS: sni -> servername(JS 不删除 sni,无明确规范)
			if srIsShadowsocksOverTls(transformed) {
				if IsPresent(transformed, "sni") {
					transformed["servername"] = GetString(transformed, "sni")
				}
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

		// 处理xhttp参数
		if proxyType == "vless" && network == "xhttp" {
			if xhttpOpts := GetMap(transformed, "xhttp-opts"); xhttpOpts != nil {
				transformed["obfs"] = network
				if IsPresent(transformed, "xhttp-opts", "path") {
					if path, ok := xhttpOpts["path"].(string); ok {
						transformed["path"] = path
					}
				}

				if headers := GetMap(xhttpOpts, "headers"); headers != nil {
					if IsPresent(transformed, "xhttp-opts", "headers", "Host") {
						if host, ok := headers["Host"].(string); ok {
							transformed["obfsParam"] = host
						}
					}
				}
			}
		}

		// 兼容0.3.7后续版本xhttp改为splithttp的情况
		if proxyType == "vless" && network == "splithttp" {
			transformed["network"] = "xhttp"
			transformed["obfs"] = "xhttp"
			if splithttpOpts := GetMap(transformed, "splithttp-opts"); splithttpOpts != nil {
				if IsPresent(transformed, "splithttp-opts", "path") {
					if path, ok := splithttpOpts["path"].(string); ok {
						transformed["path"] = path
					}
				}

				if headers := GetMap(splithttpOpts, "headers"); headers != nil {
					if IsPresent(transformed, "splithttp-opts", "headers", "Host") {
						if host, ok := headers["Host"].(string); ok {
							transformed["obfsParam"] = host
						}
					}
				}
			}
		}

		// Handle H2 network options(对齐 JS 188-220)
		if (proxyType == "vmess" || proxyType == "vless") && network == "h2" {
			if h2Opts := GetMap(transformed, "h2-opts"); h2Opts != nil {
				// path 为数组时取首元素(JS: Array.isArray(path) => path[0])
				if IsPresent(transformed, "h2-opts", "path") {
					if pathSlice, ok := h2Opts["path"].([]interface{}); ok && len(pathSlice) > 0 {
						h2Opts["path"] = pathSlice[0]
					}
				}

				// host 优先级: h2-opts.host ?? headers.host ?? headers.Host
				headers := GetMap(h2Opts, "headers")
				hasHostKey := IsPresent(transformed, "h2-opts", "host") ||
					IsPresent(transformed, "h2-opts", "headers", "host") ||
					IsPresent(transformed, "h2-opts", "headers", "Host")
				if hasHostKey {
					var hostVal interface{}
					if IsPresent(transformed, "h2-opts", "host") {
						hostVal = h2Opts["host"]
					} else if headers != nil && IsPresent(headers, "host") {
						hostVal = headers["host"]
					} else if headers != nil && IsPresent(headers, "Host") {
						hostVal = headers["Host"]
					}
					// 写入 h2-opts.host,确保为数组(JS: Array.isArray(host) ? host : [host])
					if _, ok := hostVal.([]interface{}); ok {
						h2Opts["host"] = hostVal
					} else if hostSlice, ok := hostVal.([]string); ok {
						h2Opts["host"] = hostSlice
					} else {
						h2Opts["host"] = []interface{}{hostVal}
					}
				}

				// 删除 headers.host / headers.Host,若 headers 清空则删除 headers
				if headers != nil {
					delete(headers, "host")
					delete(headers, "Host")
					if len(headers) == 0 {
						delete(h2Opts, "headers")
					}
				}
			}
		}

		// Handle WS network early data(对齐 JS 221-228)
		if network == "ws" {
			wsOpts := GetMap(transformed, "ws-opts")
			if wsOpts == nil {
				wsOpts = make(map[string]interface{})
				transformed["ws-opts"] = wsOpts
			}
			if GetString(wsOpts, "path") == "" {
				wsOpts["path"] = "/"
			}
			normalizeWsEarlyDataPath(wsOpts)
		}

		// Handle plugin-opts TLS
		// JS: pluginOpts['skip-cert-verify'] = pluginOpts['skip-cert-verify'] || proxy['skip-cert-verify']
		if pluginOpts := GetMap(transformed, "plugin-opts"); pluginOpts != nil {
			if GetBool(pluginOpts, "tls") && IsPresent(transformed, "skip-cert-verify") {
				pluginOpts["skip-cert-verify"] = GetBool(pluginOpts, "skip-cert-verify") || GetBool(transformed, "skip-cert-verify")
			}
		}

		// Delete tls for certain proxy types(对齐 JS 237-250)
		deleteTLSTypes := map[string]bool{
			"trojan": true, "tuic": true, "hysteria": true,
			"hysteria2": true, "juicity": true, "anytls": true,
			"trusttunnel": true, "naive": true,
		}
		if deleteTLSTypes[proxyType] {
			delete(transformed, "tls")
		}

		// Handle tls-fingerprint -> fingerprint
		if IsPresent(transformed, "tls-fingerprint") {
			transformed["fingerprint"] = GetString(transformed, "tls-fingerprint")
		}
		delete(transformed, "tls-fingerprint")

		// Handle underlying-proxy -> dialer-proxy
		if IsPresent(transformed, "underlying-proxy") {
			transformed["dialer-proxy"] = GetString(transformed, "underlying-proxy")
		}
		delete(transformed, "underlying-proxy")

		// Remove invalid tls field
		if IsPresent(transformed, "tls") {
			if _, ok := transformed["tls"].(bool); !ok {
				delete(transformed, "tls")
			}
		}

		// Clean up fields(对齐 JS 265-271)
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
			// JS: deleteHttpUpgradeEarlyDataMetadata(proxy[`${network}-opts`]) —— 删除 _v2ray-http-upgrade-ed
			if network != "" {
				if netOpts := GetMap(transformed, network+"-opts"); netOpts != nil {
					delete(netOpts, "_v2ray-http-upgrade-ed")
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

	// Generate YAML string
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
