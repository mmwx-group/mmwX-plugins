package substore

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ClashProducer implements the Producer interface for Clash format
type ClashProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewClashProducer creates a new Clash producer
func NewClashProducer() *ClashProducer {
	return &ClashProducer{
		producerType: "clash",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *ClashProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Clash format
func (p *ClashProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	// Supported ciphers for Shadowsocks
	supportedSSCiphers := map[string]bool{
		"aes-128-gcm":              true,
		"aes-192-gcm":              true,
		"aes-256-gcm":              true,
		"aes-128-cfb":              true,
		"aes-192-cfb":              true,
		"aes-256-cfb":              true,
		"aes-128-ctr":              true,
		"aes-192-ctr":              true,
		"aes-256-ctr":              true,
		"rc4-md5":                  true,
		"chacha20-ietf":            true,
		"xchacha20":                true,
		"chacha20-ietf-poly1305":   true,
		"xchacha20-ietf-poly1305":  true,
	}

	// Filter proxies
	filtered := make([]Proxy, 0)
	for _, proxy := range proxies {
		proxyType := p.helper.GetProxyType(proxy)

		// Skip if include-unsupported-proxy is not set
		if !opts.IncludeUnsupportedProxy {
			// Check supported proxy types
			supportedTypes := map[string]bool{
				"ss": true, "ssr": true, "vmess": true, "vless": true,
				"socks5": true, "http": true, "snell": true, "trojan": true,
				"wireguard": true,
			}

			if !supportedTypes[proxyType] {
				continue
			}

			// Check SS cipher
			if proxyType == "ss" {
				cipher := GetString(proxy, "cipher")
				if !supportedSSCiphers[cipher] {
					continue
				}
			}

			// Check Snell version
			if proxyType == "snell" {
				version := GetInt(proxy, "version")
				if version >= 4 {
					continue
				}
			}

			// Check VLESS flow and reality
			// JS: typeof proxy.flow !== 'undefined' —— 只要存在 flow 键即过滤(含空串/null),
			// 因此用 map 键存在性判断而非 IsPresent(后者对 nil 返回 false)。
			if proxyType == "vless" {
				if _, hasFlow := proxy["flow"]; hasFlow || proxy["reality-opts"] != nil {
					continue
				}
			}

			// Check ws network with v2ray-http-upgrade (not supported by Clash)
			network := GetString(proxy, "network")
			if network == "ws" {
				if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
					if GetBool(wsOpts, "v2ray-http-upgrade") {
						continue
					}
				}
			}

			// Check dialer proxy
			if IsPresent(proxy, "underlying-proxy") || IsPresent(proxy, "dialer-proxy") {
				// Clash doesn't support dialer proxy, skip this node
				continue
			}
		}

		filtered = append(filtered, proxy)
	}

	// Transform proxies
	result := make([]Proxy, 0)
	for _, proxy := range filtered {
		transformed := p.helper.CloneProxy(proxy)
		proxyType := p.helper.GetProxyType(transformed)

		// Type-specific transformations
		switch proxyType {
		case "vmess":
			// Handle aead
			if IsPresent(transformed, "aead") {
				if GetBool(transformed, "aead") {
					transformed["alterId"] = 0
				}
				delete(transformed, "aead")
			}

			// Handle sni -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}

			// Handle cipher
			// JS: proxy.cipher = normalizeClashVmessSecurity(proxy.cipher) —— 无条件赋值,
			// 即使 cipher 缺失也会被规范化为 fallback "auto"。
			transformed["cipher"] = clashNormalizeVmessSecurity(GetString(transformed, "cipher"))

		case "wireguard":
			// WireGuard keepalive
			if !IsPresent(transformed, "keepalive") {
				if IsPresent(transformed, "persistent-keepalive") {
					transformed["keepalive"] = GetInt(transformed, "persistent-keepalive")
				}
			}
			transformed["persistent-keepalive"] = GetInt(transformed, "keepalive")

			// preshared-key
			if !IsPresent(transformed, "preshared-key") {
				if IsPresent(transformed, "pre-shared-key") {
					transformed["preshared-key"] = GetString(transformed, "pre-shared-key")
				}
			}
			transformed["pre-shared-key"] = GetString(transformed, "preshared-key")

			// allowed-ips: 确保是数组类型
			if IsPresent(transformed, "allowed-ips") {
				allowedIPs := transformed["allowed-ips"]
				switch v := allowedIPs.(type) {
				case string:
					// 如果是字符串，尝试解析为数组
					if v != "" {
						// 尝试 JSON 解析
						var arr []string
						if err := json.Unmarshal([]byte(v), &arr); err == nil {
							transformed["allowed-ips"] = arr
						} else {
							// 如果 JSON 解析失败，按逗号分割
							parts := strings.Split(v, ",")
							arr := make([]string, 0, len(parts))
							for _, part := range parts {
								if trimmed := strings.TrimSpace(part); trimmed != "" {
									arr = append(arr, trimmed)
								}
							}
							if len(arr) > 0 {
								transformed["allowed-ips"] = arr
							}
						}
					}
				case []interface{}:
					// 已经是数组，保持不变
				case []string:
					// 已经是字符串数组，保持不变
				}
			}

		case "snell":
			version := GetInt(transformed, "version")
			if version < 3 {
				delete(transformed, "udp")
			}

		case "vless":
			// Handle sni -> servername
			if IsPresent(transformed, "sni") {
				transformed["servername"] = GetString(transformed, "sni")
				delete(transformed, "sni")
			}
		}

		// Handle HTTP network options
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

				// host 来源优先级: h2-opts.host > headers.host > headers.Host,
				// 最终写到 h2-opts.host 并确保为数组(JS 同款逻辑)。
				headers := GetMap(h2Opts, "headers")
				hasHost := IsPresent(transformed, "h2-opts", "host") ||
					(headers != nil && (IsPresent(headers, "host") || IsPresent(headers, "Host")))
				if hasHost {
					var host interface{}
					if v, ok := h2Opts["host"]; ok && v != nil {
						host = v
					} else if headers != nil {
						if v, ok := headers["host"]; ok && v != nil {
							host = v
						} else if v, ok := headers["Host"]; ok && v != nil {
							host = v
						}
					}
					switch host.(type) {
					case []interface{}, []string:
						h2Opts["host"] = host
					default:
						h2Opts["host"] = []interface{}{host}
					}
				}

				// headers 中的 host/Host 已迁移到 h2-opts.host,删除之;若 headers 清空则移除。
				if headers != nil {
					delete(headers, "host")
					delete(headers, "Host")
					if len(headers) == 0 {
						delete(h2Opts, "headers")
					}
				}
			}
		}

		// Handle WebSocket early data
		// JS: 先确保 ws-opts 存在且 path 默认 "/", 再调用 normalizeWebSocketEarlyDataPath。
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
		// JS: plugin-opts.skip-cert-verify ||= proxy.skip-cert-verify —— OR 取真,不覆盖已有 true。
		if pluginOpts := GetMap(transformed, "plugin-opts"); pluginOpts != nil {
			if GetBool(pluginOpts, "tls") && IsPresent(transformed, "skip-cert-verify") {
				pluginOpts["skip-cert-verify"] = GetBool(pluginOpts, "skip-cert-verify") || GetBool(transformed, "skip-cert-verify")
			}
		}

		// Delete tls for certain proxy types
		deleteTLSTypes := map[string]bool{
			"trojan": true, "tuic": true, "hysteria": true,
			"hysteria2": true, "juicity": true, "anytls": true,
			"trusttunnel": true, "naive": true,
		}
		if deleteTLSTypes[proxyType] {
			delete(transformed, "tls")
		}

		// Handle tls-fingerprint -> fingerprint
		// JS: if (proxy['tls-fingerprint']) —— 仅在 truthy(非空串)时迁移。
		if fp := GetString(transformed, "tls-fingerprint"); fp != "" {
			transformed["fingerprint"] = fp
		}
		delete(transformed, "tls-fingerprint")

		// Remove invalid tls field
		if IsPresent(transformed, "tls") {
			if _, ok := transformed["tls"].(bool); !ok {
				delete(transformed, "tls")
			}
		}

		// Clean up fields
		// JS 还会删除 ip-cidr / ipv6-cidr。
		p.helper.RemoveProxyFields(transformed,
			"subName", "collectionName", "id", "resolved", "no-resolve",
			"ip-cidr", "ipv6-cidr")

		// Remove null and underscore-prefixed fields for non-internal output
		// 注意:underscore 前缀匹配大小写不敏感(JS /^_/i,但 _ 无大小写,等价于前缀判断)。
		if outputType != "internal" {
			for key := range transformed {
				if transformed[key] == nil || strings.HasPrefix(key, "_") {
					delete(transformed, key)
				}
			}
			// 删除 http-upgrade 早数据元字段(JS deleteHttpUpgradeEarlyDataMetadata)。
			if netOpts := GetMap(transformed, network+"-opts"); netOpts != nil {
				delete(netOpts, "_v2ray-http-upgrade-ed")
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

// clashVmessSecurityAliases 镜像 JS VMESS_SECURITY_ALIASES。
var clashVmessSecurityAliases = map[string]string{
	"chacha20-ietf-poly1305": "chacha20-poly1305",
}

// clashVmessSecurityClashValues 镜像 JS VMESS_SECURITY_CLASH_VALUES。
var clashVmessSecurityClashValues = []string{
	"auto", "aes-128-gcm", "chacha20-poly1305", "none",
}

// clashNormalizeVmessSecurity 镜像 JS normalizeClashVmessSecurity:
// 规范化(trim+lowercase)、按别名归一、对照 CLASH 支持值校验,均不命中时回退 "auto"。
func clashNormalizeVmessSecurity(security string) string {
	normalized := strings.ToLower(strings.TrimSpace(security))
	const fallback = "auto"
	if normalized == "" {
		return fallback
	}

	for _, v := range clashVmessSecurityClashValues {
		if strings.ToLower(strings.TrimSpace(v)) == normalized {
			// 命中支持值后仍走别名归一(JS canonicalizeVmessSecurity)。
			if canonical, ok := clashVmessSecurityAliases[normalized]; ok {
				return canonical
			}
			return normalized
		}
	}

	// 别名归一后再比对一次(acceptAliases 分支)。
	canonical := normalized
	if c, ok := clashVmessSecurityAliases[normalized]; ok {
		canonical = c
	}
	for _, v := range clashVmessSecurityClashValues {
		sv := strings.ToLower(strings.TrimSpace(v))
		if c, ok := clashVmessSecurityAliases[sv]; ok {
			sv = c
		}
		if sv == canonical {
			return canonical
		}
	}

	return fallback
}

// clashEdQueryRegex 用于提取/剥离 ws path 中的 ?ed=<digits> 参数。
var clashEdDigitsRegex = regexp.MustCompile(`^\d+$`)

// clashExtractPathQueryParam 镜像 JS extractPathQueryParam:
// 从 path 的 query 中剥离指定参数,返回剥离后的 path 与首个非空命中值。
func clashExtractPathQueryParam(rawPath, paramName string) (string, string) {
	path := rawPath
	queryIndex := strings.Index(path, "?")
	if queryIndex == -1 {
		return path, ""
	}

	basePath := path[:queryIndex]
	query := path[queryIndex+1:]
	keptParts := make([]string, 0)
	value := ""

	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		key, val := clashSplitQueryPart(part)
		if key == paramName {
			if value == "" && val != "" {
				value = val
			}
			continue
		}
		keptParts = append(keptParts, part)
	}

	if len(keptParts) > 0 {
		return basePath + "?" + strings.Join(keptParts, "&"), value
	}
	return basePath, value
}

// clashSplitQueryPart 镜像 JS splitQueryPart,按首个 '=' 分割并 URL 解码。
func clashSplitQueryPart(part string) (string, string) {
	sep := strings.Index(part, "=")
	if sep == -1 {
		return clashDecodeQueryComponent(part), ""
	}
	return clashDecodeQueryComponent(part[:sep]), clashDecodeQueryComponent(part[sep+1:])
}

// clashDecodeQueryComponent 镜像 JS decodeQueryComponent(+ 视为空格),解码失败时返回原值。
func clashDecodeQueryComponent(value string) string {
	if decoded, err := url.QueryUnescape(value); err == nil {
		return decoded
	}
	return value
}

// clashGetPathQueryParam 镜像 JS getPathQueryParam,只读取不剥离。
func clashGetPathQueryParam(rawPath, paramName string) string {
	queryIndex := strings.Index(rawPath, "?")
	if queryIndex == -1 {
		return ""
	}
	for _, part := range strings.Split(rawPath[queryIndex+1:], "&") {
		if part == "" {
			continue
		}
		key, val := clashSplitQueryPart(part)
		if key == paramName && val != "" {
			return val
		}
	}
	return ""
}

// normalizeWsEarlyDataPath 镜像 JS normalizeWebSocketEarlyDataPath(transport-path.js)。
// 从 ws-opts.path 的 ?ed= 参数提取早数据,设置 early-data-header-name / max-early-data。
// 通用实现,clash 与 shadowrocket 共用同一份(单一来源,避免格式逻辑分叉)。
func normalizeWsEarlyDataPath(wsOpts map[string]interface{}) {
	if wsOpts == nil {
		return
	}
	networkPath := GetString(wsOpts, "path")
	// JS getSafeIntegerPathQueryParam:仅当 ed 为合法整数时 value 才非空,否则视为 ''。
	rawEd := clashGetPathQueryParam(networkPath, "ed")
	ed := ""
	var maxEarlyData int
	hasMaxEarlyData := false
	if clashEdDigitsRegex.MatchString(rawEd) {
		if n, err := strconv.Atoi(rawEd); err == nil {
			ed = rawEd
			maxEarlyData = n
			hasMaxEarlyData = true
		}
	}

	if GetBool(wsOpts, "v2ray-http-upgrade") {
		if ed != "" {
			strippedPath, _ := clashExtractPathQueryParam(networkPath, "ed")
			wsOpts["path"] = strippedPath
			wsOpts["v2ray-http-upgrade-fast-open"] = true
			if GetString(wsOpts, "_v2ray-http-upgrade-ed") == "" {
				wsOpts["_v2ray-http-upgrade-ed"] = ed
			}
		}
		delete(wsOpts, "early-data-header-name")
		delete(wsOpts, "max-early-data")
		return
	}

	if ed == "" {
		return
	}

	strippedPath, _ := clashExtractPathQueryParam(networkPath, "ed")
	wsOpts["path"] = strippedPath
	if !IsPresent(wsOpts, "early-data-header-name") {
		wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
	}
	if !IsPresent(wsOpts, "max-early-data") && hasMaxEarlyData {
		wsOpts["max-early-data"] = maxEarlyData
	}
}
