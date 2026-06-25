package substore

import (
	"fmt"
	"regexp"
	"strings"
)

// SurfboardProducer implements the Producer interface for Surfboard format
type SurfboardProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewSurfboardProducer creates a new Surfboard producer
func NewSurfboardProducer() *SurfboardProducer {
	return &SurfboardProducer{
		producerType: "surfboard",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *SurfboardProducer) GetType() string {
	return p.producerType
}

// surfboardDigitsRegex 提取字符串中第一段连续数字(对齐 JS 的 `${proxy.down}`.match(/\d+/))
var surfboardDigitsRegex = regexp.MustCompile(`\d+`)

// surfboardHasNonBlankValue 对齐 JS hasNonBlankValue: 非 nil 且 trim 后非空
func surfboardHasNonBlankValue(m map[string]interface{}, key string) bool {
	val, ok := m[key]
	if !ok || val == nil {
		return false
	}
	return strings.TrimSpace(fmt.Sprintf("%v", val)) != ""
}

// surfboardAppendTlsParams 对齐 JS appendTlsProxyParams:
// 追加 server-cert-fingerprint-sha256 / sni(带引号) / skip-cert-verify。
// enabled=false 时整体跳过(对应 vmess/http/socks5 仅在 tls 时追加)。
func (p *SurfboardProducer) surfboardAppendTlsParams(result *Result, proxy Proxy, enabled bool) {
	if !enabled {
		return
	}

	result.AppendIfPresent(",server-cert-fingerprint-sha256=%v", "tls-fingerprint")

	// SNI - 兼容 SubStore 的 "sni" 与 miaomiaowu 的 "servername";JS 中带引号
	if sni := GetSNI(proxy); sni != "" {
		result.Append(fmt.Sprintf(`,sni="%s"`, sni))
	}

	result.AppendIfPresent(",skip-cert-verify=%v", "skip-cert-verify")
}

// Produce converts a single proxy to Surfboard format
// For Surfboard, we expect proxies to be converted one by one
func (p *SurfboardProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	results := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		result, err := p.produceSingle(proxy)
		if err != nil {
			// Skip unsupported proxies if configured
			if opts.IncludeUnsupportedProxy {
				continue
			}
			return nil, err
		}
		results = append(results, result)
	}

	return strings.Join(results, "\n"), nil
}

// produceSingle converts a single proxy to Surfboard format string
func (p *SurfboardProducer) produceSingle(proxy Proxy) (string, error) {
	// Check for unsupported ws network with v2ray-http-upgrade
	if GetString(proxy, "network") == "ws" {
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if GetBool(wsOpts, "v2ray-http-upgrade") {
				return "", fmt.Errorf("platform Surfboard does not support network ws with http upgrade")
			}
		}
	}

	// Clean proxy name (remove = and , characters)
	name := GetString(proxy, "name")
	name = strings.ReplaceAll(name, "=", "")
	name = strings.ReplaceAll(name, ",", "")
	proxy["name"] = name

	proxyType := p.helper.GetProxyType(proxy)
	switch proxyType {
	case "ss":
		return p.shadowsocks(proxy)
	case "trojan":
		return p.trojan(proxy)
	case "vmess":
		return p.vmess(proxy)
	case "http":
		return p.http(proxy)
	case "snell":
		return p.snell(proxy)
	case "socks5":
		return p.socks5(proxy)
	case "hysteria2":
		return p.hysteria2(proxy)
	case "wireguard-surge":
		return p.wireguard(proxy)
	}

	if proxyType == "anytls" {
		// JS: 有 network 且(非 tcp,或 tcp 但带 reality-opts)则不支持
		if IsPresent(proxy, "network") {
			network := GetString(proxy, "network")
			if network != "tcp" || IsPresent(proxy, "reality-opts") {
				return "", fmt.Errorf("platform Surfboard does not support proxy type %s with network or REALITY", proxyType)
			}
		}
		return p.anytls(proxy)
	}

	return "", fmt.Errorf("platform Surfboard does not support proxy type: %s", proxyType)
}

// hysteria2 converts a hysteria2 proxy to Surfboard format
func (p *SurfboardProducer) hysteria2(proxy Proxy) (string, error) {
	if IsPresent(proxy, "obfs") || IsPresent(proxy, "obfs-password") {
		return "", fmt.Errorf("Surfboard Hysteria2 does not support obfs")
	}

	result := NewResult(proxy)
	result.Append(fmt.Sprintf("%s=hysteria2,%s,%d",
		GetString(proxy, "name"), GetString(proxy, "server"), GetInt(proxy, "port")))

	result.AppendIfPresent(`,password="%v"`, "password")

	if surfboardHasNonBlankValue(proxy, "ports") {
		ports := strings.ReplaceAll(GetAnyString(proxy, "ports"), ",", ";")
		result.Append(fmt.Sprintf(`,port-hopping="%s"`, ports))
	}

	if surfboardHasNonBlankValue(proxy, "hop-interval") {
		result.Append(fmt.Sprintf(",port-hopping-interval=%s", GetAnyString(proxy, "hop-interval")))
	}

	// tls verification
	p.surfboardAppendTlsParams(result, proxy, true)

	// download-bandwidth: 提取 down 中的首段数字,无则 0(对齐 JS)
	if IsPresent(proxy, "down") {
		down := surfboardDigitsRegex.FindString(GetAnyString(proxy, "down"))
		if down == "" {
			down = "0"
		}
		result.Append(fmt.Sprintf(",download-bandwidth=%s", down))
	}

	// udp
	result.AppendIfPresent(",udp-relay=%v", "udp")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// anytls converts an anytls proxy to Surfboard format
func (p *SurfboardProducer) anytls(proxy Proxy) (string, error) {
	result := NewResult(proxy)
	result.Append(fmt.Sprintf("%s=%s,%s,%d",
		GetString(proxy, "name"), GetString(proxy, "type"),
		GetString(proxy, "server"), GetInt(proxy, "port")))

	result.AppendIfPresent(`,password="%v"`, "password")

	// tls verification
	p.surfboardAppendTlsParams(result, proxy, true)

	// tfo
	result.AppendIfPresent(",tfo=%v", "tfo")

	// udp
	result.AppendIfPresent(",udp-relay=%v", "udp")

	// reuse
	result.AppendIfPresent(",reuse=%v", "reuse")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// snell converts a snell proxy to Surfboard format
func (p *SurfboardProducer) snell(proxy Proxy) (string, error) {
	if IsPresent(proxy, "version") {
		version := GetInt(proxy, "version")
		if version != 1 && version != 2 && version != 3 && version != 4 && version != 5 {
			return "", fmt.Errorf("platform Surfboard does not support snell version %v", proxy["version"])
		}
	}

	result := NewResult(proxy)
	result.Append(fmt.Sprintf("%s=%s,%s,%d",
		GetString(proxy, "name"), GetString(proxy, "type"),
		GetString(proxy, "server"), GetInt(proxy, "port")))

	result.AppendIfPresent(",version=%v", "version")
	result.AppendIfPresent(`,psk="%v"`, "psk")

	// obfs
	result.AppendIfPresent(",obfs=%v", "obfs-opts.mode")
	result.AppendIfPresent(",obfs-host=%v", "obfs-opts.host")
	result.AppendIfPresent(",obfs-uri=%v", "obfs-opts.path")

	// tfo
	result.AppendIfPresent(",tfo=%v", "tfo")

	// udp (仅 version >= 3)
	if GetInt(proxy, "version") >= 3 {
		result.AppendIfPresent(",udp-relay=%v", "udp")
	}

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// shadowsocks converts a shadowsocks proxy to Surfboard format
func (p *SurfboardProducer) shadowsocks(proxy Proxy) (string, error) {
	result := NewResult(proxy)

	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	proxyType := GetString(proxy, "type")

	result.Append(fmt.Sprintf("%s=%s,%s,%d", name, proxyType, server, port))

	// Validate cipher
	cipher := GetString(proxy, "cipher")
	supportedCiphers := map[string]bool{
		"aes-128-gcm":             true,
		"aes-192-gcm":             true,
		"aes-256-gcm":             true,
		"chacha20-ietf-poly1305":  true,
		"xchacha20-ietf-poly1305": true,
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
		"salsa20":                 true,
		"chacha20":                true,
		"chacha20-ietf":           true,
		"2022-blake3-aes-128-gcm": true,
		"2022-blake3-aes-256-gcm": true,
	}

	if !supportedCiphers[cipher] {
		return "", fmt.Errorf("cipher %s is not supported", cipher)
	}

	result.Append(fmt.Sprintf(",encrypt-method=%s", cipher))

	result.AppendIfPresent(`,password="%v"`, "password")

	// Handle obfs plugin
	if IsPresent(proxy, "plugin") {
		plugin := GetString(proxy, "plugin")
		if plugin == "obfs" {
			pluginOpts := GetMap(proxy, "plugin-opts")
			if pluginOpts != nil {
				result.Append(fmt.Sprintf(",obfs=%s", GetString(pluginOpts, "mode")))
				result.AppendIfPresent(",obfs-host=%v", "plugin-opts.host")
				result.AppendIfPresent(",obfs-uri=%v", "plugin-opts.path")
			}
		} else {
			return "", fmt.Errorf("plugin %s is not supported", plugin)
		}
	}

	// UDP relay
	result.AppendIfPresent(",udp-relay=%v", "udp")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// trojan converts a trojan proxy to Surfboard format
func (p *SurfboardProducer) trojan(proxy Proxy) (string, error) {
	result := NewResult(proxy)

	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	proxyType := GetString(proxy, "type")

	result.Append(fmt.Sprintf("%s=%s,%s,%d", name, proxyType, server, port))

	result.AppendIfPresent(",password=%v", "password")

	// Transport
	if err := p.handleTransport(result, proxy); err != nil {
		return "", err
	}

	// TLS
	result.AppendIfPresent(",tls=%v", "tls")

	// tls verification
	p.surfboardAppendTlsParams(result, proxy, true)

	// TFO
	result.AppendIfPresent(",tfo=%v", "tfo")

	// UDP relay
	result.AppendIfPresent(",udp-relay=%v", "udp")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// vmess converts a vmess proxy to Surfboard format
func (p *SurfboardProducer) vmess(proxy Proxy) (string, error) {
	result := NewResult(proxy)

	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	proxyType := GetString(proxy, "type")

	result.Append(fmt.Sprintf("%s=%s,%s,%d", name, proxyType, server, port))

	result.AppendIfPresent(",username=%v", "uuid")

	// Transport
	if err := p.handleTransport(result, proxy); err != nil {
		return "", err
	}

	// AEAD
	if IsPresent(proxy, "aead") {
		result.Append(fmt.Sprintf(",vmess-aead=%v", GetBool(proxy, "aead")))
	} else {
		alterId := GetInt(proxy, "alterId")
		result.Append(fmt.Sprintf(",vmess-aead=%v", alterId == 0))
	}

	// TLS
	result.AppendIfPresent(",tls=%v", "tls")

	// tls verification (仅在 tls 为真时追加,对齐 JS Boolean(proxy.tls))
	p.surfboardAppendTlsParams(result, proxy, GetBool(proxy, "tls"))

	// UDP relay
	result.AppendIfPresent(",udp-relay=%v", "udp")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// http converts an http proxy to Surfboard format
func (p *SurfboardProducer) http(proxy Proxy) (string, error) {
	result := NewResult(proxy)

	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	tls := GetBool(proxy, "tls")

	proxyType := "http"
	if tls {
		proxyType = "https"
	}

	result.Append(fmt.Sprintf("%s=%s,%s,%d", name, proxyType, server, port))

	result.AppendIfPresent(",%v", "username")
	result.AppendIfPresent(",%v", "password")

	// tls verification (仅在 tls 为真时追加)
	p.surfboardAppendTlsParams(result, proxy, tls)

	// UDP relay
	result.AppendIfPresent(",udp-relay=%v", "udp")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// socks5 converts a socks5 proxy to Surfboard format
func (p *SurfboardProducer) socks5(proxy Proxy) (string, error) {
	result := NewResult(proxy)

	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	tls := GetBool(proxy, "tls")

	proxyType := "socks5"
	if tls {
		proxyType = "socks5-tls"
	}

	result.Append(fmt.Sprintf("%s=%s,%s,%d", name, proxyType, server, port))

	result.AppendIfPresent(",%v", "username")
	result.AppendIfPresent(",%v", "password")

	// tls verification (仅在 tls 为真时追加)
	p.surfboardAppendTlsParams(result, proxy, tls)

	// UDP relay
	result.AppendIfPresent(",udp-relay=%v", "udp")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// wireguard converts a wireguard proxy to Surfboard format
func (p *SurfboardProducer) wireguard(proxy Proxy) (string, error) {
	result := NewResult(proxy)

	name := GetString(proxy, "name")
	result.Append(fmt.Sprintf("%s=wireguard", name))

	result.AppendIfPresent(",section-name=%v", "section-name")

	result.AppendIfPresent(",block-quic=%v", "block-quic")

	return result.String(), nil
}

// handleTransport handles transport layer configuration
func (p *SurfboardProducer) handleTransport(result *Result, proxy Proxy) error {
	if !IsPresent(proxy, "network") {
		return nil
	}

	network := GetString(proxy, "network")
	switch {
	case network == "ws":
		result.Append(",ws=true")

		if IsPresent(proxy, "ws-opts") {
			result.AppendIfPresent(",ws-path=%v", "ws-opts.path")

			if IsPresent(proxy, "ws-opts", "headers") {
				headers := GetMap(GetMap(proxy, "ws-opts"), "headers")
				if headers != nil {
					headerParts := make([]string, 0)
					for k, v := range headers {
						value := fmt.Sprintf("%v", v)
						// Quote Host header value
						if k == "Host" {
							value = fmt.Sprintf(`"%s"`, value)
						}
						headerParts = append(headerParts, fmt.Sprintf("%s:%s", k, value))
					}
					joined := strings.Join(headerParts, "|")
					if IsNotBlank(joined) {
						result.Append(fmt.Sprintf(",ws-headers=%s", joined))
					}
				}
			}
		}
	case network == "tcp" && IsPresent(proxy, "reality-opts"):
		// 对齐 JS:tcp + reality 不支持
		return fmt.Errorf("reality is unsupported")
	case network != "tcp":
		// 对齐 JS:非 tcp(非 ws)网络不支持
		return fmt.Errorf("network %s is unsupported", network)
	}

	return nil
}
