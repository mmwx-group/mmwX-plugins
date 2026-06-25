package substore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// URIProducer implements URI scheme encoding for various proxy protocols
type URIProducer struct {
	producerType string
}

// NewURIProducer creates a new URI producer
func NewURIProducer() *URIProducer {
	return &URIProducer{
		producerType: "uri",
	}
}

// GetType returns the producer type
func (p *URIProducer) GetType() string {
	return p.producerType
}

// isIPv6 checks if a string is an IPv6 address
func isIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// uriEncodeComponent 对齐 JS encodeURIComponent:
//   - 空格编码为 %20 (而非 url.QueryEscape 的 +)
//   - 不转义 ! ' ( ) * - _ . ~ 及字母数字
//
// 这是 URI producer 的关键编码差异: 直接用 url.QueryEscape 会把空格变成 +
// 导致部分客户端把节点名/参数解析错误。
func uriEncodeComponent(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		// encodeURIComponent 不转义的字符集
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' ||
			c == '\'' || c == '(' || c == ')' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0F])
		}
	}
	return b.String()
}

// uriTruthy 镜像 JS 真值判断 (if (proxy[key]))。注意:JS 中数字 0 为假,但字符串 "0" 为真;
// 空串/nil/false/数字 0 视为假,其余为真。
func uriTruthy(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	default:
		return true
	}
}

// uriFirstString 取值: 若为数组取首元素, 否则转字符串。对齐 JS Array.isArray(x) ? x[0] : x。
func uriFirstString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []interface{}:
		if len(t) > 0 {
			return fmt.Sprintf("%v", t[0])
		}
		return ""
	case []string:
		if len(t) > 0 {
			return t[0]
		}
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

// uriNormalizePluginMux 对齐 JS normalizePluginMuxValue: bool→0/1, 数字字符串→原值, 否则空。
// 返回空串表示不输出 mux。
func uriNormalizePluginMux(mux interface{}) string {
	switch v := mux.(type) {
	case nil:
		return ""
	case bool:
		if v {
			return "1"
		}
		return "0"
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%d", int64(v))
	case string:
		n := strings.ToLower(strings.TrimSpace(v))
		if n == "true" {
			return "1"
		}
		if n == "false" {
			return "0"
		}
		if regexpDigits.MatchString(n) {
			return n
		}
		return ""
	default:
		return ""
	}
}

var regexpDigits = regexp.MustCompile(`^\d+$`)

// uriVmessSecurityAliases 对齐 JS vmess-security.js 的别名映射
var uriVmessSecurityAliases = map[string]string{
	"chacha20-ietf-poly1305": "chacha20-poly1305",
}

// uriVmessSecurityCommon 对齐 JS VMESS_SECURITY_COMMON_VALUES
var uriVmessSecurityCommon = map[string]bool{
	"auto":              true,
	"none":              true,
	"zero":              true,
	"aes-128-gcm":       true,
	"chacha20-poly1305": true,
}

// uriNormalizeVmessSecurity 对齐 JS normalizeVmessSecurity:
// 归一化 cipher 到受支持的值, 不支持则回退 "auto"。
func uriNormalizeVmessSecurity(security string) string {
	normalized := strings.ToLower(strings.TrimSpace(security))
	if normalized == "" {
		return "auto"
	}
	if uriVmessSecurityCommon[normalized] {
		if canonical, ok := uriVmessSecurityAliases[normalized]; ok {
			return canonical
		}
		return normalized
	}
	// 别名归一后再次匹配
	if canonical, ok := uriVmessSecurityAliases[normalized]; ok {
		if uriVmessSecurityCommon[canonical] {
			return canonical
		}
	}
	return "auto"
}

// uriGetWireGuardAddressWithCIDR 对齐 JS getWireGuardAddressWithCIDR:
// 读取 ip/ipv6 及其 *-cidr, 返回 "host/cidr"。无效地址返回空串。
func uriGetWireGuardAddressWithCIDR(proxy Proxy, family string) string {
	var addrKey, cidrKey string
	var defaultCIDR int
	if family == "ipv6" {
		addrKey, cidrKey, defaultCIDR = "ipv6", "ipv6-cidr", 128
	} else {
		addrKey, cidrKey, defaultCIDR = "ip", "ip-cidr", 32
	}
	host := strings.TrimSpace(GetString(proxy, addrKey))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" {
		return ""
	}
	max := 32
	if family == "ipv6" {
		max = 128
	}
	cidr := defaultCIDR
	if IsPresent(proxy, cidrKey) {
		if c := GetInt(proxy, cidrKey); c >= 0 && c <= max {
			cidr = c
		}
	}
	return fmt.Sprintf("%s/%d", host, cidr)
}

// preprocessProxy performs preprocessing on proxy before encoding
// This matches the frontend logic in uri.ts lines 268-291
func preprocessProxy(proxy Proxy) Proxy {
	// Clone proxy to avoid modifying original
	processed := make(Proxy)
	for k, v := range proxy {
		processed[k] = v
	}

	// Delete metadata fields
	delete(processed, "subName")
	delete(processed, "collectionName")
	delete(processed, "id")
	delete(processed, "resolved")
	delete(processed, "no-resolve")

	// Convert servername to sni if sni doesn't exist
	if servername := GetString(processed, "servername"); servername != "" && GetString(processed, "sni") == "" {
		processed["sni"] = servername
	}

	// Remove null/empty values
	for key := range processed {
		if processed[key] == nil || processed[key] == "" {
			delete(processed, key)
		}
	}

	// Delete tls field for certain protocols
	proxyType := GetString(processed, "type")
	if proxyType == "trojan" || proxyType == "tuic" || proxyType == "hysteria" ||
		proxyType == "hysteria2" || proxyType == "juicity" {
		delete(processed, "tls")
	}

	// Add brackets for IPv6 addresses (except vmess)
	if proxyType != "vmess" {
		if server := GetString(processed, "server"); server != "" && isIPv6(server) {
			processed["server"] = "[" + server + "]"
		}
	}

	return processed
}

// Produce converts all proxies to URI format, one per line
func (p *URIProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if len(proxies) == 0 {
		return "", nil
	}

	// Process all proxies and collect URIs
	var uris []string
	for _, proxy := range proxies {
		// Preprocess proxy (matches frontend logic)
		proxy = preprocessProxy(proxy)
		proxyType := GetString(proxy, "type")

		var uri string
		var err error

		switch proxyType {
		case "vmess":
			uri, err = p.encodeVMess(proxy)
		case "vless":
			uri, err = p.encodeVLESS(proxy)
		case "trojan":
			uri, err = p.encodeTrojan(proxy)
		case "ss":
			uri, err = p.encodeShadowsocks(proxy)
		case "ssr":
			uri, err = p.encodeShadowsocksR(proxy)
		case "hysteria2":
			uri, err = p.encodeHysteria2(proxy)
		case "hysteria":
			uri, err = p.encodeHysteria(proxy)
		case "tuic":
			uri, err = p.encodeTUIC(proxy)
		case "socks5":
			uri, err = p.encodeSOCKS5(proxy)
		case "http":
			uri, err = p.encodeHTTP(proxy)
		case "wireguard":
			uri, err = p.encodeWireGuard(proxy)
		case "anytls":
			uri, err = p.encodeAnyTLS(proxy)
		case "naive":
			uri, err = p.encodeNaive(proxy)
		case "mieru":
			uri, err = p.encodeMieru(proxy)
		default:
			// Skip unsupported proxy types instead of returning error
			continue
		}

		if err != nil {
			// Skip proxies that fail to encode
			continue
		}

		uris = append(uris, uri)
	}

	// Join all URIs with newline
	return strings.Join(uris, "\n"), nil
}

// ProduceOne is a helper to encode a single proxy
func (p *URIProducer) ProduceOne(proxy Proxy) (string, error) {
	result, err := p.Produce([]Proxy{proxy}, "", nil)
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

// encodeVMess encodes VMess proxy to vmess:// URI (matches frontend)
func (p *URIProducer) encodeVMess(proxy Proxy) (string, error) {
	// Handle network type conversion (frontend line 376-386)
	network := GetString(proxy, "network")
	net := network
	if net == "" {
		// JS: net = proxy.network || 'tcp'
		net = "tcp"
	}
	typeField := ""

	if network == "http" {
		net = "tcp"
		typeField = "http"
	} else if network == "ws" {
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if GetBool(wsOpts, "v2ray-http-upgrade") {
				net = "httpupgrade"
			}
		}
	}

	config := map[string]interface{}{
		"v":    "2",
		"ps":   GetString(proxy, "name"),
		"add":  GetString(proxy, "server"),
		"port": fmt.Sprintf("%d", GetInt(proxy, "port")),
		"id":   GetString(proxy, "uuid"),
		"aid":  fmt.Sprintf("%d", GetInt(proxy, "alterId")),
		"scy":  uriNormalizeVmessSecurity(GetString(proxy, "cipher")),
		"net":  net,
		"type": typeField,
		"tls":  "",
	}

	// TLS
	if GetBool(proxy, "tls") {
		config["tls"] = "tls"
		if sni := GetString(proxy, "sni"); sni != "" {
			config["sni"] = sni
		}
	}

	// ALPN
	if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
		config["alpn"] = strings.Join(alpn, ",")
	}

	// Fingerprint
	if fp := GetString(proxy, "client-fingerprint"); fp != "" {
		config["fp"] = fp
	}

	// 注: JS vmess 配置对象不包含 udp 字段(此前 Go 多输出 udp, 已移除以对齐 JS)。

	// Network specific options (frontend line 411-454)
	if network != "" {
		switch network {
		case "grpc":
			if grpcOpts := GetMap(proxy, "grpc-opts"); grpcOpts != nil {
				config["path"] = GetString(grpcOpts, "grpc-service-name")
				// https://github.com/XTLS/Xray-core/issues/91
				config["type"] = GetString(grpcOpts, "_grpc-type")
				if config["type"] == "" {
					config["type"] = "gun"
				}
				if authority := GetString(grpcOpts, "_grpc-authority"); authority != "" {
					config["host"] = authority
				}
			}
		case "kcp", "quic":
			if opts := GetMap(proxy, network+"-opts"); opts != nil {
				typeKey := "_" + network + "-type"
				hostKey := "_" + network + "-host"
				pathKey := "_" + network + "-path"
				config["type"] = GetString(opts, typeKey)
				if config["type"] == "" {
					config["type"] = "none"
				}
				if host := GetString(opts, hostKey); host != "" {
					config["host"] = host
				}
				if path := GetString(opts, pathKey); path != "" {
					config["path"] = path
				}
			}
		default:
			// ws, http, h2, etc.
			if opts := GetMap(proxy, network+"-opts"); opts != nil {
				if path := opts["path"]; path != nil {
					if pathSlice, ok := path.([]interface{}); ok && len(pathSlice) > 0 {
						config["path"] = fmt.Sprintf("%v", pathSlice[0])
					} else if pathStr, ok := path.(string); ok {
						config["path"] = pathStr
					}
				}
				if headers := GetMap(opts, "headers"); headers != nil {
					if host := headers["Host"]; host != nil {
						if hostSlice, ok := host.([]interface{}); ok && len(hostSlice) > 0 {
							config["host"] = fmt.Sprintf("%v", hostSlice[0])
						} else if hostStr, ok := host.(string); ok {
							config["host"] = hostStr
						}
					}
				}
			}
		}
	}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(jsonBytes)
	return "vmess://" + encoded, nil
}

// encodeVLESS encodes VLESS proxy to vless:// URI
func (p *URIProducer) encodeVLESS(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	uuid := GetString(proxy, "uuid")
	name := GetString(proxy, "name")

	params := url.Values{}

	// Security
	security := "none"
	if GetBool(proxy, "tls") {
		security = "tls"
	}
	if realityOpts := GetMap(proxy, "reality-opts"); realityOpts != nil {
		security = "reality"
		if pubKey := GetString(realityOpts, "public-key"); pubKey != "" {
			params.Set("pbk", pubKey)
		}
		if shortID := GetAnyString(realityOpts, "short-id"); shortID != "" {
			params.Set("sid", shortID)
		}
		if spiderX := GetString(realityOpts, "_spider-x"); spiderX != "" {
			params.Set("spx", spiderX)
		}
	}
	params.Set("security", security)

	// SNI
	// 注: preprocessProxy 已将 servername 复制到 sni, JS 读 proxy.sni。
	if sni := GetSNI(proxy); sni != "" {
		params.Set("sni", sni)
	}

	// ALPN
	if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
		params.Set("alpn", strings.Join(alpn, ","))
	}

	// Fingerprint
	if fp := GetString(proxy, "client-fingerprint"); fp != "" {
		params.Set("fp", fp)
	}

	// tls-fingerprint → pcs (JS line 596-598)
	if pcs := GetString(proxy, "tls-fingerprint"); pcs != "" {
		params.Set("pcs", pcs)
	}

	// _h2 (JS line 591-594)
	if GetBool(proxy, "_h2") {
		params.Set("h2", "1")
	}

	// Flow
	if flow := GetString(proxy, "flow"); flow != "" {
		params.Set("flow", flow)
	}

	// Skip cert verify
	if GetBool(proxy, "skip-cert-verify") {
		params.Set("allowInsecure", "1")
	}

	// Encryption
	if encryption := GetString(proxy, "encryption"); encryption != "" {
		params.Set("encryption", encryption)
	}

	// Network type (JS line 652-664)
	network := GetString(proxy, "network")
	vlessType := network
	switch network {
	case "splithttp":
		vlessType = "xhttp"
	case "ws":
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if GetBool(wsOpts, "v2ray-http-upgrade") {
				vlessType = "httpupgrade"
			}
		}
	case "http":
		// JS: vlessType = 'tcp', 并追加 headerType=http
		vlessType = "tcp"
	case "h2":
		// JS: vlessType = 'http'
		vlessType = "http"
	}

	if vlessType != "" {
		params.Set("type", vlessType)
	}
	if network == "http" {
		params.Set("headerType", "http")
		// http-opts.method (JS line 719-723)
		if httpOpts := GetMap(proxy, "http-opts"); httpOpts != nil {
			if method := GetString(httpOpts, "method"); method != "" {
				params.Set("method", method)
			}
		}
	}

	// Mode, extra, pqv parameters (frontend line 175-182)
	if mode := GetString(proxy, "_mode"); mode != "" {
		params.Set("mode", mode)
	}
	if extra := GetString(proxy, "_extra"); extra != "" {
		params.Set("extra", extra)
	}
	if pqv := GetString(proxy, "_pqv"); pqv != "" {
		params.Set("pqv", pqv)
	}

	// Network-specific options
	switch network {
	case "ws":
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if path := GetString(wsOpts, "path"); path != "" {
				params.Set("path", path)
			}
			if headers := GetMap(wsOpts, "headers"); headers != nil {
				if host := GetString(headers, "Host"); host != "" {
					params.Set("host", host)
				}
			}
		}
	case "grpc":
		if grpcOpts := GetMap(proxy, "grpc-opts"); grpcOpts != nil {
			if serviceName := GetString(grpcOpts, "grpc-service-name"); serviceName != "" {
				params.Set("serviceName", serviceName)
			}
			// Frontend line 195-201: grpc mode and authority
			grpcType := GetString(grpcOpts, "_grpc-type")
			if grpcType == "" {
				grpcType = "gun"
			}
			params.Set("mode", grpcType)
			if authority := GetString(grpcOpts, "_grpc-authority"); authority != "" {
				params.Set("authority", authority)
			}
		}
	case "xhttp":
		// Frontend line 204-206: splithttp/xhttp mode
		if mode := GetString(proxy, "mode"); mode != "" {
			params.Set("mode", mode)
		} else {
			params.Set("mode", "auto")
		}
		if xhttpOpts := GetMap(proxy, "xhttp-opts"); xhttpOpts != nil {
			if path := GetString(xhttpOpts, "path"); path != "" {
				params.Set("path", path)
			}
			if headers := GetMap(xhttpOpts, "headers"); headers != nil {
				if host := GetString(headers, "Host"); host != "" {
					params.Set("host", host)
				}
			}
		}

	case "splithttp":
		params.Set("type", "xhttp")
		// Frontend line 204-206: splithttp mode
		if mode := GetString(proxy, "mode"); mode != "" {
			params.Set("mode", mode)
		} else {
			params.Set("mode", "auto")
		}
		if splithttpOpts := GetMap(proxy, "splithttp-opts"); splithttpOpts != nil {
			if path := GetString(splithttpOpts, "path"); path != "" {
				params.Set("path", path)
			}
			if headers := GetMap(splithttpOpts, "headers"); headers != nil {
				if host := GetString(headers, "Host"); host != "" {
					params.Set("host", host)
				}
			}
		}
	case "kcp":
		// JS line 724-733: seed/headerType 取自 proxy 根字段 (非 kcp-opts)
		if seed := GetString(proxy, "seed"); seed != "" {
			params.Set("seed", seed)
		}
		if headerType := GetString(proxy, "headerType"); headerType != "" {
			params.Set("headerType", headerType)
		}
	}

	// packetEncoding (JS line 751-774)
	// 注: JS VLESS 不输出 udp 参数, 而是按 packet-encoding/xudp/packet-addr/udp 推导 packetEncoding。
	canonicalPacketEncoding := ""
	hasPacketEncoding := false
	if pe, ok := proxy["packet-encoding"]; ok && pe != nil {
		canonicalPacketEncoding = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", pe)))
		hasPacketEncoding = true
	} else if GetBool(proxy, "xudp") {
		canonicalPacketEncoding = "xudp"
		hasPacketEncoding = true
	} else if GetBool(proxy, "packet-addr") {
		canonicalPacketEncoding = "packetaddr"
		hasPacketEncoding = true
	} else if u, ok := proxy["udp"]; ok {
		if b, ok := u.(bool); ok && b {
			// udp === true → canonicalPacketEncoding = '' → packetEncoding=none
			canonicalPacketEncoding = ""
			hasPacketEncoding = true
		}
	}
	if hasPacketEncoding {
		switch canonicalPacketEncoding {
		case "":
			params.Set("packetEncoding", "none")
		case "packetaddr":
			params.Set("packetEncoding", "packet")
		case "xudp":
			params.Set("packetEncoding", "xudp")
		}
	}

	// fragment 用 uriEncodeComponent 对齐 JS encodeURIComponent(proxy.name)
	// (url.PathEscape 不会转义 & = , 等, 与 JS 不一致)。
	uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		uuid, server, port, params.Encode(), uriEncodeComponent(name))
	return uri, nil
}

// encodeTrojan encodes Trojan proxy to trojan:// URI
func (p *URIProducer) encodeTrojan(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	params := url.Values{}

	// SNI
	sni := GetString(proxy, "sni")
	if sni == "" {
		sni = GetString(proxy, "servername")
	}
	if sni == "" {
		sni = server
	}
	params.Set("sni", sni)

	// Skip cert verify
	if GetBool(proxy, "skip-cert-verify") {
		params.Set("allowInsecure", "1")
	}

	// ALPN
	if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
		params.Set("alpn", strings.Join(alpn, ","))
	}

	// Fingerprint
	if fp := GetString(proxy, "client-fingerprint"); fp != "" {
		params.Set("fp", fp)
	}

	// tls-fingerprint → pcs (JS line 1189-1194)
	if pcs := GetString(proxy, "tls-fingerprint"); pcs != "" {
		params.Set("pcs", pcs)
	}

	// Reality support (frontend line 526-555)
	if realityOpts := GetMap(proxy, "reality-opts"); realityOpts != nil {
		params.Set("security", "reality")
		if pubKey := GetString(realityOpts, "public-key"); pubKey != "" {
			params.Set("pbk", pubKey)
		}
		if shortID := GetAnyString(realityOpts, "short-id"); shortID != "" {
			params.Set("sid", shortID)
		}
		if spiderX := GetString(realityOpts, "_spider-x"); spiderX != "" {
			params.Set("spx", spiderX)
		}
		if extra := GetString(proxy, "_extra"); extra != "" {
			params.Set("extra", extra)
		}
		if mode := GetString(proxy, "_mode"); mode != "" {
			params.Set("mode", mode)
		}
	}

	// Network type (frontend line 461-470)
	network := GetString(proxy, "network")
	trojanType := network
	if network == "ws" {
		if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
			if GetBool(wsOpts, "v2ray-http-upgrade") {
				trojanType = "httpupgrade"
			}
		}
	}
	if trojanType != "" {
		params.Set("type", trojanType)

		// Network-specific options
		switch network {
		case "ws":
			if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil {
				if path := GetString(wsOpts, "path"); path != "" {
					params.Set("path", path)
				}
				if headers := GetMap(wsOpts, "headers"); headers != nil {
					if host := GetString(headers, "Host"); host != "" {
						params.Set("host", host)
					}
				}
			}
		case "grpc":
			if grpcOpts := GetMap(proxy, "grpc-opts"); grpcOpts != nil {
				if serviceName := GetString(grpcOpts, "grpc-service-name"); serviceName != "" {
					params.Set("serviceName", serviceName)
				}
				// Frontend line 476-491: grpc authority and mode
				if authority := GetString(grpcOpts, "_grpc-authority"); authority != "" {
					params.Set("authority", authority)
				}
				grpcType := GetString(grpcOpts, "_grpc-type")
				if grpcType == "" {
					grpcType = "gun"
				}
				params.Set("mode", grpcType)
			}
		}
	}

	// 注: JS trojan 不输出 udp 参数, 故此处不再追加 (此前 Go 多输出 udp, 已纠正)。

	// fragment 用 uriEncodeComponent 对齐 JS encodeURIComponent(proxy.name)。
	uri := fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
		password, server, port, params.Encode(), uriEncodeComponent(name))
	return uri, nil
}

// encodeShadowsocks encodes Shadowsocks proxy to ss:// URI (aligned to JS uri.js case 'ss')
// 重要纠正点:
//  1. 2022-blake3-* cipher 不做 base64, 而是 encodeURIComponent(cipher):encodeURIComponent(password)
//  2. 补齐 transport(type/grpc/ws path+host)、fp、alpn、reality(security/pbk/sid/spx/mode/extra)、security=tls
//  3. v2ray-plugin 同时输出 mode/host(兼容), 并补 path/tls/sni/skip-cert-verify/mux
//  4. JS ss 不输出 udp 参数(此前 Go 多输出, 已移除)
//
// 注: 为与 JS encodeURIComponent 的编码一致(空格 %20 而非 +, 保留 ; 的转义),
// 此处手动拼接 query 字符串, 不用 url.Values.Encode()(它会把空格编码为 + 并排序 key)。
func (p *URIProducer) encodeShadowsocks(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	cipher := GetString(proxy, "cipher")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	// userinfo: 2022-blake3-* 不 base64 (JS line 828-832)
	var userInfoPart string
	if strings.HasPrefix(cipher, "2022-blake3-") {
		userInfoPart = uriEncodeComponent(cipher) + ":" + uriEncodeComponent(password)
	} else {
		userInfoPart = base64.StdEncoding.EncodeToString([]byte(cipher + ":" + password))
	}

	plugin := GetString(proxy, "plugin")
	pluginSlash := ""
	if plugin != "" {
		pluginSlash = "/"
	}
	uri := fmt.Sprintf("ss://%s@%s:%d%s", userInfoPart, server, port, pluginSlash)

	// query 以 "&" 起头, 末尾 replace(/^&/, '?') (JS line 834-997)
	var query strings.Builder

	if plugin != "" {
		opts := GetMap(proxy, "plugin-opts")
		query.WriteString("&plugin=")
		switch plugin {
		case "obfs":
			s := fmt.Sprintf("simple-obfs;obfs=%s", GetString(opts, "mode"))
			if host := GetString(opts, "host"); host != "" {
				s += ";obfs-host=" + host
			}
			query.WriteString(uriEncodeComponent(s))
		case "v2ray-plugin":
			mode := GetString(opts, "mode")
			host := GetString(opts, "host")
			s := fmt.Sprintf("v2ray-plugin;obfs=%s;mode=%s", mode, mode)
			if host != "" {
				s += ";obfs-host=" + host + ";host=" + host
			}
			if path := GetString(opts, "path"); path != "" {
				s += ";path=" + path
			}
			if GetBool(opts, "tls") {
				s += ";tls"
			}
			if sni := GetString(opts, "sni"); sni != "" {
				s += ";sni=" + sni
			}
			if scv, ok := opts["skip-cert-verify"]; ok && scv != nil {
				s += fmt.Sprintf(";skip-cert-verify=%v", scv)
			}
			if mux := uriNormalizePluginMux(opts["mux"]); mux != "" {
				s += ";mux=" + mux
			}
			query.WriteString(uriEncodeComponent(s))
		case "shadow-tls":
			s := fmt.Sprintf("shadow-tls;host=%s;password=%s;version=%d",
				GetString(opts, "host"), GetString(opts, "password"), GetInt(opts, "version"))
			query.WriteString(uriEncodeComponent(s))
		default:
			return "", fmt.Errorf("unsupported plugin option: %s", plugin)
		}
	}

	// uot / tfo (JS line 875-880); 注: JS ss 不输出 udp
	if GetBool(proxy, "udp-over-tcp") {
		query.WriteString("&uot=1")
	}
	if GetBool(proxy, "tfo") {
		query.WriteString("&tfo=1")
	}

	// transport (JS line 881-946)
	network := GetString(proxy, "network")
	if network != "" {
		ssType := network
		if network == "ws" {
			if wsOpts := GetMap(proxy, "ws-opts"); wsOpts != nil && GetBool(wsOpts, "v2ray-http-upgrade") {
				ssType = "httpupgrade"
			}
		}
		query.WriteString("&type=" + uriEncodeComponent(ssType))
		if network == "grpc" {
			if grpcOpts := GetMap(proxy, "grpc-opts"); grpcOpts != nil {
				if sn := GetString(grpcOpts, "grpc-service-name"); sn != "" {
					query.WriteString("&serviceName=" + uriEncodeComponent(sn))
				}
				if auth := GetString(grpcOpts, "_grpc-authority"); auth != "" {
					query.WriteString("&authority=" + uriEncodeComponent(auth))
				}
				gt := GetString(grpcOpts, "_grpc-type")
				if gt == "" {
					gt = "gun"
				}
				query.WriteString("&mode=" + uriEncodeComponent(gt))
			}
		}
		// path/host (JS 913-945); ws/其它 transport-opts
		if opts := GetMap(proxy, network+"-opts"); opts != nil {
			path := uriFirstString(opts["path"])
			if path != "" {
				query.WriteString("&path=" + uriEncodeComponent(path))
			}
			if headers := GetMap(opts, "headers"); headers != nil {
				host := uriFirstString(headers["Host"])
				if host != "" {
					query.WriteString("&host=" + uriEncodeComponent(host))
				}
			}
		}
	}

	// alpn / fp (JS line 947-960)
	if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
		query.WriteString("&alpn=" + uriEncodeComponent(strings.Join(alpn, ",")))
	}
	if fp := GetString(proxy, "client-fingerprint"); fp != "" {
		query.WriteString("&fp=" + uriEncodeComponent(fp))
	}

	// security / reality (JS line 961-993)
	if realityOpts := GetMap(proxy, "reality-opts"); realityOpts != nil {
		query.WriteString("&security=reality")
		if pbk := GetString(realityOpts, "public-key"); pbk != "" {
			query.WriteString("&pbk=" + uriEncodeComponent(pbk))
		}
		if sid := GetAnyString(realityOpts, "short-id"); sid != "" {
			query.WriteString("&sid=" + uriEncodeComponent(sid))
		}
		if spx := GetString(realityOpts, "_spider-x"); spx != "" {
			query.WriteString("&spx=" + uriEncodeComponent(spx))
		}
		if extra := GetString(proxy, "_extra"); extra != "" {
			query.WriteString("&extra=" + uriEncodeComponent(extra))
		}
		if mode := GetString(proxy, "_mode"); mode != "" {
			query.WriteString("&mode=" + uriEncodeComponent(mode))
		}
	} else if GetBool(proxy, "tls") {
		query.WriteString("&security=tls")
	}

	// sni / allowInsecure 仅在 tls 时输出 (JS line 989-993)
	if GetBool(proxy, "tls") {
		sni := GetString(proxy, "sni")
		if sni == "" {
			sni = server
		}
		query.WriteString("&sni=" + uriEncodeComponent(sni))
		if GetBool(proxy, "skip-cert-verify") {
			query.WriteString("&allowInsecure=1")
		}
	}

	q := query.String()
	if len(q) > 0 && q[0] == '&' {
		q = "?" + q[1:]
	}
	uri += q + "#" + uriEncodeComponent(name)
	return uri, nil
}

// encodeShadowsocksR encodes ShadowsocksR proxy to ssr:// URI (aligned to JS uri.js case 'ssr')
// 重要纠正点:
//  1. 参数名 protocolparam (此前 Go 写成 protoparam, 会导致 SSR 协议参数失效)
//  2. 全部使用标准 base64(含 padding), 非 URL-safe; 外层 ssr:// 也用标准 base64
//     (此前 Go 用 URLEncoding 并裁剪 padding, 与 JS Base64.encode 不一致)
//  3. query 顺序: remarks → obfsparam → protocolparam, 且手动拼接(不排序)
func (p *URIProducer) encodeShadowsocksR(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	protocol := GetString(proxy, "protocol")
	cipher := GetString(proxy, "cipher")
	obfs := GetString(proxy, "obfs")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	std := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	main := fmt.Sprintf("%s:%d:%s:%s:%s:%s/", server, port, protocol, cipher, obfs, std(password))

	var q strings.Builder
	q.WriteString("?remarks=" + std(name))
	if obfsParam := GetString(proxy, "obfs-param"); obfsParam != "" {
		q.WriteString("&obfsparam=" + std(obfsParam))
	}
	if protocolParam := GetString(proxy, "protocol-param"); protocolParam != "" {
		q.WriteString("&protocolparam=" + std(protocolParam))
	}

	return "ssr://" + std(main+q.String()), nil
}

// encodeHysteria2 encodes Hysteria2 proxy to hysteria2:// URI (aligned to JS uri.js case 'hysteria2')
// 对齐要点: 按 JS 顺序手动拼接 query; sni 取 proxy.sni(经 preprocess 已含 servername);
// password 用 encodeURIComponent。
// 有意偏离: JS 不输出 alpn / udp 参数; 此处亦不输出以保持一致。
func (p *URIProducer) encodeHysteria2(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	var ps []string

	// hop-interval, keepalive (JS line 1243-1250) —— 不编码值, 与 JS 一致
	if hopInterval := GetAnyString(proxy, "hop-interval"); hopInterval != "" {
		ps = append(ps, "hop-interval="+hopInterval)
	}
	if keepalive := proxy["keepalive"]; keepalive != nil && fmt.Sprintf("%v", keepalive) != "" {
		ps = append(ps, fmt.Sprintf("keepalive=%v", keepalive))
	}
	// skip-cert-verify → insecure=1
	if GetBool(proxy, "skip-cert-verify") {
		ps = append(ps, "insecure=1")
	}
	// obfs / obfs-password
	if obfs := GetString(proxy, "obfs"); obfs != "" {
		ps = append(ps, "obfs="+uriEncodeComponent(obfs))
		if obfsPassword := GetString(proxy, "obfs-password"); obfsPassword != "" {
			ps = append(ps, "obfs-password="+uriEncodeComponent(obfsPassword))
		}
	}
	// sni
	if sni := GetSNI(proxy); sni != "" {
		ps = append(ps, "sni="+uriEncodeComponent(sni))
	}
	// ports → mport
	if ports := GetAnyString(proxy, "ports"); ports != "" {
		ps = append(ps, "mport="+ports)
	}
	// tls-fingerprint → pinSHA256
	if tlsFingerprint := GetString(proxy, "tls-fingerprint"); tlsFingerprint != "" {
		ps = append(ps, "pinSHA256="+uriEncodeComponent(tlsFingerprint))
	}
	// tfo → fastopen
	if GetBool(proxy, "tfo") {
		ps = append(ps, "fastopen=1")
	}

	uri := fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
		uriEncodeComponent(password), server, port, strings.Join(ps, "&"), uriEncodeComponent(name))
	return uri, nil
}

// encodeHysteria encodes Hysteria proxy to hysteria:// URI (completely rewritten to match frontend)
func (p *URIProducer) encodeHysteria(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	name := GetString(proxy, "name")

	hysteriaParams := []string{}

	// Frontend line 624-671: Iterate through all keys with complex mapping
	for key := range proxy {
		if key == "name" || key == "type" || key == "server" || key == "port" {
			continue
		}

		val := proxy[key]
		if val == nil {
			continue
		}

		// 注: JS 仅在 default 分支判断 /^_/ 跳过; _obfs 有专门分支需在此之前处理,
		// 故不能在循环开头统一跳过下划线前缀(此前 Go 在此 continue, 会误丢 _obfs)。

		// Special mappings (JS line 1295-1334)
		switch key {
		case "alpn":
			if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
				hysteriaParams = append(hysteriaParams, "alpn="+uriEncodeComponent(alpn[0]))
			} else if s := uriFirstString(val); s != "" {
				hysteriaParams = append(hysteriaParams, "alpn="+uriEncodeComponent(s))
			}
		case "skip-cert-verify":
			if GetBool(proxy, "skip-cert-verify") {
				hysteriaParams = append(hysteriaParams, "insecure=1")
			}
		case "tfo", "fast-open":
			if GetBool(proxy, key) {
				hasParam := false
				for _, pp := range hysteriaParams {
					if pp == "fastopen=1" {
						hasParam = true
						break
					}
				}
				if !hasParam {
					hysteriaParams = append(hysteriaParams, "fastopen=1")
				}
			}
		case "ports":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("mport=%v", val))
		case "auth-str":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("auth=%v", val))
		case "up":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("upmbps=%v", val))
		case "down":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("downmbps=%v", val))
		case "_obfs":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("obfs=%v", val))
		case "obfs":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("obfsParam=%v", val))
		case "sni":
			hysteriaParams = append(hysteriaParams, fmt.Sprintf("peer=%v", val))
		default:
			// JS: else if (proxy[key] && !/^_/i.test(key))
			// 仅处理 truthy 且非下划线前缀; key.replace(/-/,'_') 只替换首个连字符。
			if strings.HasPrefix(key, "_") {
				continue
			}
			if !uriTruthy(val) {
				continue
			}
			paramKey := strings.Replace(key, "-", "_", 1)
			hysteriaParams = append(hysteriaParams, paramKey+"="+uriEncodeComponent(fmt.Sprintf("%v", val)))
		}
	}

	// fragment 用 uriEncodeComponent 对齐 JS encodeURIComponent(proxy.name)。
	uri := fmt.Sprintf("hysteria://%s:%d?%s#%s",
		server, port, strings.Join(hysteriaParams, "&"), uriEncodeComponent(name))
	return uri, nil
}

// encodeTUIC encodes TUIC proxy to tuic:// URI (completely rewritten to match frontend)
// Frontend line 680-749: Only process when token is not present
func (p *URIProducer) encodeTUIC(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	uuid := GetString(proxy, "uuid")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	// Frontend line 681: Only process if no token
	token := GetString(proxy, "token")
	if token != "" && len(token) > 0 {
		// Skip if token exists
		return "", fmt.Errorf("TUIC with token is not supported in URI format")
	}

	tuicParams := []string{}

	// Frontend line 683-740: Iterate through all keys with complex mapping
	for key := range proxy {
		if key == "name" || key == "type" || key == "uuid" || key == "password" ||
			key == "server" || key == "port" || key == "tls" {
			continue
		}

		val := proxy[key]
		if val == nil {
			continue
		}

		// Skip keys starting with underscore
		if strings.HasPrefix(key, "_") {
			continue
		}

		// Special mappings (frontend line 695-738)
		paramKey := strings.ReplaceAll(key, "-", "_")
		switch key {
		case "alpn":
			if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
				tuicParams = append(tuicParams, fmt.Sprintf("alpn=%s", url.QueryEscape(alpn[0])))
			}
		case "skip-cert-verify":
			if GetBool(proxy, "skip-cert-verify") {
				tuicParams = append(tuicParams, "allow_insecure=1")
			}
		case "tfo", "fast-open":
			if GetBool(proxy, key) {
				// Only add once
				hasParam := false
				for _, p := range tuicParams {
					if p == "fast_open=1" {
						hasParam = true
						break
					}
				}
				if !hasParam {
					tuicParams = append(tuicParams, "fast_open=1")
				}
			}
		case "disable-sni", "reduce-rtt":
			if GetBool(proxy, key) {
				tuicParams = append(tuicParams, fmt.Sprintf("%s=1", strings.ReplaceAll(key, "-", "_")))
			}
		case "congestion-controller":
			tuicParams = append(tuicParams, fmt.Sprintf("congestion_control=%v", val))
		case "udp":
			if udpBool, ok := val.(bool); ok {
				if udpBool {
					tuicParams = append(tuicParams, "udp=1")
				} else {
					tuicParams = append(tuicParams, "udp=0")
				}
			}
		default:
			// Other parameters: replace - with _ and encode
			tuicParams = append(tuicParams, fmt.Sprintf("%s=%s", strings.ReplaceAll(paramKey, "-", "_"), url.QueryEscape(fmt.Sprintf("%v", val))))
		}
	}

	// Build auth part: uuid:password (frontend line 742-744)
	auth := url.PathEscape(uuid)
	if password != "" {
		auth = url.PathEscape(uuid) + ":" + url.PathEscape(password)
	}

	uri := fmt.Sprintf("tuic://%s@%s:%d?%s#%s",
		auth, server, port, strings.Join(tuicParams, "&"), url.PathEscape(name))
	return uri, nil
}

// encodeSOCKS5 encodes SOCKS5 proxy to socks:// URI (matches frontend)
func (p *URIProducer) encodeSOCKS5(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	username := GetString(proxy, "username")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	// Encode username:password in Base64 (matches frontend line 298-302)
	userInfo := fmt.Sprintf("%s:%s", username, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(userInfo))

	// UDP parameter
	params := ""
	if udp, ok := proxy["udp"]; ok {
		if udpBool, ok := udp.(bool); ok {
			if udpBool {
				params = "?udp=1"
			} else {
				params = "?udp=0"
			}
		}
	}

	uri := fmt.Sprintf("socks://%s@%s:%d%s#%s",
		url.PathEscape(encoded), server, port, params, url.PathEscape(name))
	return uri, nil
}

func (p *URIProducer) encodeHTTP(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	username := GetString(proxy, "username")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")
	tls := GetBool(proxy, "tls")

	scheme := "http"
	if tls {
		scheme = "https"
	}

	var authPart string
	if username != "" {
		authPart = url.PathEscape(username) + ":" + url.PathEscape(password) + "@"
	}

	uri := fmt.Sprintf("%s://%s%s:%d#%s",
		scheme, authPart, server, port, url.PathEscape(name))
	return uri, nil
}

// encodeWireGuard encodes WireGuard proxy to wireguard:// URI (matches frontend)
func (p *URIProducer) encodeWireGuard(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	privateKey := GetString(proxy, "private-key")
	name := GetString(proxy, "name")
	ip := GetString(proxy, "ip")
	ipv6 := GetString(proxy, "ipv6")

	params := url.Values{}

	// Public key (frontend line 811-812)
	if publicKey := GetString(proxy, "public-key"); publicKey != "" {
		params.Set("publickey", publicKey)
	}

	// Address (frontend line 823-831)
	if ip != "" && ipv6 != "" {
		params.Set("address", fmt.Sprintf("%s/32,%s/128", ip, ipv6))
	} else if ip != "" {
		params.Set("address", fmt.Sprintf("%s/32", ip))
	} else if ipv6 != "" {
		params.Set("address", fmt.Sprintf("%s/128", ipv6))
	}

	// Other parameters
	for key, val := range proxy {
		if key == "name" || key == "type" || key == "server" || key == "port" ||
			key == "ip" || key == "ipv6" || key == "private-key" || key == "public-key" {
			continue
		}
		if strings.HasPrefix(key, "_") {
			continue
		}
		if key == "udp" {
			if udpBool, ok := val.(bool); ok {
				if udpBool {
					params.Set("udp", "1")
				} else {
					params.Set("udp", "0")
				}
			}
		} else if val != nil && val != "" {
			params.Set(key, fmt.Sprintf("%v", val))
		}
	}

	uri := fmt.Sprintf("wireguard://%s@%s:%d/?%s#%s",
		url.PathEscape(privateKey), server, port, params.Encode(), url.PathEscape(name))
	return uri, nil
}

// encodeAnyTLS encodes AnyTLS proxy to anytls:// URI (matches frontend)
func (p *URIProducer) encodeAnyTLS(proxy Proxy) (string, error) {
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	password := GetString(proxy, "password")
	name := GetString(proxy, "name")

	params := url.Values{}

	// skip-cert-verify (frontend line 756-758)
	if GetBool(proxy, "skip-cert-verify") {
		params.Set("insecure", "1")
	}

	// SNI (frontend line 761-763)
	if sni := GetString(proxy, "sni"); sni != "" {
		params.Set("sni", sni)
	}

	// client-fingerprint (frontend line 766-768)
	if fp := GetString(proxy, "client-fingerprint"); fp != "" {
		params.Set("fp", fp)
	}

	// ALPN (frontend line 771-773)
	if alpn := GetStringSlice(proxy, "alpn"); len(alpn) > 0 {
		alpnStrs := make([]string, len(alpn))
		for i, a := range alpn {
			alpnStrs[i] = url.QueryEscape(a)
		}
		params.Set("alpn", strings.Join(alpnStrs, ","))
	}

	// UDP (frontend line 776-778)
	if udp, ok := proxy["udp"]; ok {
		if udpBool, ok := udp.(bool); ok {
			if udpBool {
				params.Set("udp", "1")
			} else {
				params.Set("udp", "0")
			}
		}
	}

	// idle session parameters (frontend line 781-789)
	if val := GetString(proxy, "idle-session-check-interval"); val != "" {
		params.Set("idleSessionCheckInterval", val)
	}
	if val := GetString(proxy, "idle-session-timeout"); val != "" {
		params.Set("idleSessionTimeout", val)
	}
	if val := proxy["min-idle-session"]; val != nil {
		params.Set("minIdleSession", fmt.Sprintf("%v", val))
	}

	// Build URI (frontend line 792-794)
	uri := fmt.Sprintf("anytls://%s@%s:%d", url.PathEscape(password), server, port)
	if len(params) > 0 {
		uri += "/?" + params.Encode()
	}
	uri += "#" + url.PathEscape(name)
	return uri, nil
}

func (p *URIProducer) encodeNaive(proxy Proxy) (string, error) {
	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	username := GetString(proxy, "username")
	password := GetString(proxy, "password")

	if server == "" || port == 0 {
		return "", fmt.Errorf("missing server or port")
	}

	auth := url.PathEscape(username) + ":" + url.PathEscape(password)

	params := url.Values{}
	params.Set("security", "tls")
	if sni := GetString(proxy, "sni"); sni != "" {
		params.Set("sni", sni)
	}
	if GetBool(proxy, "udp-over-tcp") {
		params.Set("uot", "1")
	}
	if extraHeaders := GetMap(proxy, "extra-headers"); extraHeaders != nil {
		for k, v := range extraHeaders {
			params.Set("header", fmt.Sprintf("%s:%v", k, v))
		}
	}

	uri := fmt.Sprintf("naive://%s@%s:%d/?%s", auth, server, port, params.Encode())
	uri += "#" + url.PathEscape(name)
	return uri, nil
}

func (p *URIProducer) encodeMieru(proxy Proxy) (string, error) {
	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")
	username := GetString(proxy, "username")
	password := GetString(proxy, "password")

	if server == "" {
		return "", fmt.Errorf("missing server")
	}

	auth := url.PathEscape(username) + ":" + url.PathEscape(password)

	params := url.Values{}
	if transport := GetString(proxy, "transport"); transport != "" {
		params.Set("transport", transport)
	}
	if multiplexing := GetString(proxy, "multiplexing"); multiplexing != "" {
		params.Set("multiplexing", multiplexing)
	}
	if mtu := GetInt(proxy, "mtu"); mtu > 0 {
		params.Set("mtu", fmt.Sprintf("%d", mtu))
	}
	if portRange := GetString(proxy, "port-range"); portRange != "" {
		params.Set("port-range", portRange)
	}
	if tp := GetString(proxy, "traffic-pattern"); tp != "" {
		params.Set("traffic-pattern", tp)
	}

	var serverPart string
	if port > 0 {
		serverPart = fmt.Sprintf("%s:%d", server, port)
	} else {
		serverPart = server
	}

	uri := fmt.Sprintf("mieru://%s@%s/?%s", auth, serverPart, params.Encode())
	uri += "#" + url.PathEscape(name)
	return uri, nil
}
