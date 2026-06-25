// Package proxyparser 把各类代理节点 URI(vless/vmess/ss/trojan/hysteria2/tuic/naive 等)
// 解析为 clash-meta 风格的 map[string]any。零第三方依赖,供 miaomiaowu / miaomiaowux 共用。
package proxyparser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// base64DecodeURLSafe decodes URL-safe base64 string
func base64DecodeURLSafe(s string) (string, error) {
	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	// Add padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// parseQueryParams parses URL query string into map
func parseQueryParams(query string) map[string]string {
	params := make(map[string]string)
	if query == "" {
		return params
	}
	pairs := strings.Split(query, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			key, _ := url.QueryUnescape(kv[0])
			value, _ := url.QueryUnescape(kv[1])
			params[key] = value
		} else if len(kv) == 1 {
			key, _ := url.QueryUnescape(kv[0])
			params[key] = ""
		}
	}
	return params
}

// safeDecodeURIComponent safely decodes URI component, returns original on error
func safeDecodeURIComponent(s string) string {
	if s == "" {
		return s
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

func toStringMapAny(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[string]string:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out
	default:
		return nil
	}
}

func firstString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []string:
		if len(val) > 0 {
			return val[0]
		}
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func getTransportHost(node map[string]any) string {
	network, _ := node["network"].(string)
	if network == "" {
		return ""
	}

	optsKeys := []string{network + "-opts"}
	if network == "http" || network == "h2" {
		optsKeys = append(optsKeys, "h2-opts")
	}

	for _, optsKey := range optsKeys {
		opts := toStringMapAny(node[optsKey])
		if opts == nil {
			continue
		}

		headers := toStringMapAny(opts["headers"])
		if headers != nil {
			if host := firstString(headers["Host"]); host != "" {
				return host
			}
			if host := firstString(headers["host"]); host != "" {
				return host
			}
		}

		if host := firstString(opts["host"]); host != "" {
			return host
		}
	}

	return ""
}

func shouldApplyTlsSniFallback(node map[string]any) bool {
	if tls, ok := node["tls"].(bool); ok && tls {
		return true
	}
	t, _ := node["type"].(string)
	switch t {
	case "trojan", "hysteria", "hysteria2", "tuic", "anytls":
		return true
	default:
		return false
	}
}

// THIRD-PARTY BUG FIX
// 允许设置 sni 为空字符串且为防止影响其他逻辑, 这里先改成这样判断
// 本质上是为了防止本来应该使用 server 作为 sni 的情况下, 若之后进行了域名解析, 导致 server 变成 ip 丢失了 sni
// 为了兼容性, 暂时先这么改
// see https://github.com/sub-store-org/Sub-Store/commit/38e49e508b620dac29ae87178cfca80f750468ac
func applyTlsSniFallback(node map[string]any, field string) {
	if !shouldApplyTlsSniFallback(node) {
		return
	}
	if _, exists := node[field]; exists {
		return
	}
	if transportHost := getTransportHost(node); transportHost != "" {
		node[field] = transportHost
		return
	}
	server, _ := node["server"].(string)
	if server != "" && !isIP(server) {
		node[field] = server
	}
}

// parseVmessURL parses vmess:// URL and returns Clash format
func parseVmessURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "vmess://")
	jsonStr, err := base64DecodeURLSafe(content)
	if err != nil {
		return nil, fmt.Errorf("decode vmess: %w", err)
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
		return nil, fmt.Errorf("parse vmess json: %w", err)
	}

	name := getString(config, "ps", getString(config, "name", "VMess Node"))
	server := getString(config, "add", getString(config, "address", ""))
	port := getInt(config, "port", 0)
	uuid := getString(config, "id", "")
	alterId := getInt(config, "aid", 0)
	cipher := getString(config, "scy", "auto")
	network := getString(config, "net", "tcp")
	tls := getString(config, "tls", "")

	udp := true
	if v, ok := config["udp"]; ok {
		switch val := v.(type) {
		case bool:
			udp = val
		case string:
			udp = val != "false" && val != "0"
		}
	}

	node := map[string]any{
		"name":    name,
		"type":    "vmess",
		"server":  server,
		"port":    port,
		"uuid":    uuid,
		"alterId": alterId,
		"cipher":  cipher,
		"network": network,
		"udp":     udp,
		"tfo":     false,
	}

	// TLS
	node["tls"] = tls == "tls"

	// SNI/Servername
	if _, ok := config["sni"]; ok {
		node["servername"] = safeDecodeURIComponent(getString(config, "sni", ""))
	} else if host := getString(config, "host", ""); host != "" && tls == "tls" {
		node["servername"] = safeDecodeURIComponent(host)
	}

	// ALPN
	if alpn := getString(config, "alpn", ""); alpn != "" {
		node["alpn"] = strings.Split(alpn, ",")
	}

	// Client Fingerprint
	if fp := getString(config, "fp", ""); fp != "" {
		node["client-fingerprint"] = fp
	}

	// Skip cert verify
	if allowInsecure := config["allowInsecure"]; allowInsecure != nil {
		switch v := allowInsecure.(type) {
		case bool:
			node["skip-cert-verify"] = v
		case string:
			node["skip-cert-verify"] = v == "1"
		case float64:
			node["skip-cert-verify"] = v == 1
		}
	}

	// WebSocket
	if network == "ws" {
		wsOpts := map[string]any{
			"path": safeDecodeURIComponent(getString(config, "path", "/")),
		}
		if host := getString(config, "host", ""); host != "" {
			wsOpts["headers"] = map[string]string{"Host": safeDecodeURIComponent(host)}
		} else {
			wsOpts["headers"] = map[string]string{}
		}
		node["ws-opts"] = wsOpts
	}

	// HTTP/2
	if network == "h2" {
		h2Opts := map[string]any{
			"path": safeDecodeURIComponent(getString(config, "path", "/")),
		}
		if host := getString(config, "host", ""); host != "" {
			h2Opts["host"] = []string{safeDecodeURIComponent(host)}
		} else {
			h2Opts["host"] = []string{}
		}
		node["h2-opts"] = h2Opts
	}

	// gRPC
	if network == "grpc" {
		node["grpc-opts"] = map[string]any{
			"grpc-service-name": safeDecodeURIComponent(getString(config, "path", getString(config, "grpc-service-name", ""))),
		}
	}

	applyTlsSniFallback(node, "servername")

	return node, nil
}

// parseShadowsocksURL parses ss:// URL and returns Clash format
func parseShadowsocksURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "ss://")
	name := "SS Node"
	mainPart := content

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Extract query params
	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}

	mainPart = strings.TrimSuffix(mainPart, "/")

	var server, method, password string
	var port int

	if strings.Contains(mainPart, "@") {
		atIdx := strings.LastIndex(mainPart, "@")
		authPart := mainPart[:atIdx]
		if strings.Contains(authPart, "%") {
			if decoded, err := url.QueryUnescape(authPart); err == nil {
				authPart = decoded
			}
		}
		serverPart := mainPart[atIdx+1:]

		// Parse server:port
		lastColon := strings.LastIndex(serverPart, ":")
		if lastColon == -1 {
			return nil, fmt.Errorf("invalid ss url: missing port")
		}
		server = serverPart[:lastColon]
		port, _ = strconv.Atoi(serverPart[lastColon+1:])

		// Known ciphers for plaintext format detection
		knownCiphers := []string{
			"aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
			"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
			"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
			"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
			"chacha20-ietf", "chacha20", "xchacha20",
			"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
			"2022-blake3-chacha20-poly1305",
			"rc4-md5", "none",
		}

		var matchedCipher string
		for _, cipher := range knownCiphers {
			if strings.HasPrefix(authPart, cipher+":") {
				matchedCipher = cipher
				break
			}
		}

		if matchedCipher != "" {
			method = matchedCipher
			password = authPart[len(matchedCipher)+1:]
		} else {
			// base64 encoded format
			decoded, err := base64DecodeURLSafe(authPart)
			if err != nil {
				return nil, fmt.Errorf("decode ss auth: %w", err)
			}
			colonIdx := strings.Index(decoded, ":")
			if colonIdx == -1 {
				return nil, fmt.Errorf("invalid ss auth format")
			}
			method = decoded[:colonIdx]
			password = decoded[colonIdx+1:]
		}
	} else {
		// Fully encoded format
		decoded, err := base64DecodeURLSafe(mainPart)
		if err != nil {
			return nil, fmt.Errorf("decode ss: %w", err)
		}
		atIdx := strings.LastIndex(decoded, "@")
		if atIdx == -1 {
			return nil, fmt.Errorf("invalid ss format")
		}
		authPart := decoded[:atIdx]
		serverPart := decoded[atIdx+1:]

		colonIdx := strings.Index(authPart, ":")
		if colonIdx == -1 {
			return nil, fmt.Errorf("invalid ss auth")
		}
		method = authPart[:colonIdx]
		password = authPart[colonIdx+1:]

		lastColon := strings.LastIndex(serverPart, ":")
		if lastColon == -1 {
			return nil, fmt.Errorf("invalid ss server")
		}
		server = serverPart[:lastColon]
		port, _ = strconv.Atoi(serverPart[lastColon+1:])
	}

	node := map[string]any{
		"name":     name,
		"type":     "ss",
		"server":   server,
		"port":     port,
		"cipher":   method,
		"password": password,
		"udp":      true,
	}

	// Plugin
	if queryParams != nil {
		if plugin := queryParams["plugin"]; plugin != "" {
			pluginInfo := parseSSPlugin(plugin)
			if pluginInfo != nil {
				node["plugin"] = pluginInfo["plugin"]
				if opts, ok := pluginInfo["plugin-opts"]; ok {
					node["plugin-opts"] = opts
				}
				if fp, ok := pluginInfo["client-fingerprint"]; ok {
					node["client-fingerprint"] = fp
				}
			}
		}
	}

	return node, nil
}

// parseSSPlugin parses SS plugin string
func parseSSPlugin(pluginStr string) map[string]any {
	decoded, _ := url.QueryUnescape(pluginStr)
	parts := strings.Split(decoded, ";")
	if len(parts) == 0 {
		return nil
	}

	pluginName := strings.TrimSpace(parts[0])
	if pluginName == "" {
		return nil
	}

	plugin := pluginName
	if pluginName == "obfs-local" || pluginName == "simple-obfs" {
		plugin = "obfs"
	}

	opts := make(map[string]any)
	var clientFingerprint string

	for i := 1; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			continue
		}
		eqIdx := strings.Index(part, "=")
		if eqIdx == -1 {
			continue
		}
		key := part[:eqIdx]
		value := part[eqIdx+1:]

		switch plugin {
		case "obfs":
			if key == "obfs" {
				opts["mode"] = value
			} else if key == "obfs-host" || key == "host" {
				opts["host"] = value
			}
		case "v2ray-plugin", "gost-plugin":
			switch key {
			case "mode":
				opts["mode"] = value
			case "tls":
				opts["tls"] = value == "true" || value == "1"
			case "host":
				opts["host"] = value
			case "path":
				opts["path"] = value
			case "mux":
				opts["mux"] = value == "true" || value == "1"
			case "fingerprint":
				opts["fingerprint"] = value
			case "skip-cert-verify":
				opts["skip-cert-verify"] = value == "true" || value == "1"
			case "v2ray-http-upgrade":
				opts["v2ray-http-upgrade"] = value == "true" || value == "1"
			}
		case "shadow-tls":
			switch key {
			case "host":
				opts["host"] = value
			case "password":
				opts["password"] = value
			case "version":
				opts["version"], _ = strconv.Atoi(value)
			case "fp", "client-fingerprint":
				clientFingerprint = value
			}
		case "restls":
			switch key {
			case "host":
				opts["host"] = value
			case "password":
				opts["password"] = value
			case "version-hint":
				opts["version-hint"] = value
			case "restls-script":
				opts["restls-script"] = value
			case "fp", "client-fingerprint":
				clientFingerprint = value
			}
		default:
			opts[key] = value
		}
	}

	result := map[string]any{"plugin": plugin}
	if len(opts) > 0 {
		result["plugin-opts"] = opts
	}
	if clientFingerprint != "" {
		result["client-fingerprint"] = clientFingerprint
	}
	return result
}

// parseShadowsocksRURL parses ssr:// URL
func parseShadowsocksRURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "ssr://")
	decoded, err := base64DecodeURLSafe(content)
	if err != nil {
		return nil, fmt.Errorf("decode ssr: %w", err)
	}

	// Split main part and params
	parts := strings.SplitN(decoded, "/?", 2)
	mainPart := parts[0]
	paramsPart := ""
	if len(parts) > 1 {
		paramsPart = parts[1]
	}

	// Parse main part: server:port:protocol:method:obfs:base64(password)
	segments := strings.Split(mainPart, ":")
	if len(segments) < 6 {
		return nil, fmt.Errorf("invalid ssr format")
	}

	passwordBase64 := segments[len(segments)-1]
	obfs := segments[len(segments)-2]
	method := segments[len(segments)-3]
	protocol := segments[len(segments)-4]
	portStr := segments[len(segments)-5]
	server := strings.Join(segments[:len(segments)-5], ":")

	port, _ := strconv.Atoi(portStr)
	password, _ := base64DecodeURLSafe(passwordBase64)

	// Parse params
	params := parseQueryParams(paramsPart)
	name := "SSR Node"
	if remarks := params["remarks"]; remarks != "" {
		name, _ = base64DecodeURLSafe(remarks)
	}
	obfsParam := ""
	if op := params["obfsparam"]; op != "" {
		obfsParam, _ = base64DecodeURLSafe(op)
	}
	protoParam := ""
	if pp := params["protoparam"]; pp != "" {
		protoParam, _ = base64DecodeURLSafe(pp)
	}

	node := map[string]any{
		"name":     name,
		"type":     "ssr",
		"server":   server,
		"port":     port,
		"cipher":   method,
		"password": password,
		"protocol": protocol,
		"obfs":     obfs,
		"udp":      true,
	}

	if obfsParam != "" {
		node["obfs-param"] = obfsParam
	}
	if protoParam != "" {
		node["protocol-param"] = protoParam
	}

	return node, nil
}

// parseSocksURL parses socks:// or socks5:// URL
func parseSocksURL(uri string) (map[string]any, error) {
	var content string
	isPlainAuth := false

	if strings.HasPrefix(uri, "socks5://") {
		content = strings.TrimPrefix(uri, "socks5://")
		isPlainAuth = true
	} else {
		content = strings.TrimPrefix(uri, "socks://")
	}

	mainPart := content
	name := ""

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Remove query params
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		mainPart = mainPart[:idx]
	}

	var server, username, password string
	var port int

	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		// No auth
		parts := strings.Split(mainPart, ":")
		server = parts[0]
		if len(parts) > 1 {
			port, _ = strconv.Atoi(parts[1])
		}
	} else {
		authPart := mainPart[:atIdx]
		serverPart := mainPart[atIdx+1:]

		if isPlainAuth {
			colonIdx := strings.Index(authPart, ":")
			if colonIdx != -1 {
				username, _ = url.QueryUnescape(authPart[:colonIdx])
				password, _ = url.QueryUnescape(authPart[colonIdx+1:])
			} else {
				username, _ = url.QueryUnescape(authPart)
			}
		} else {
			decoded, err := base64DecodeURLSafe(authPart)
			if err == nil {
				colonIdx := strings.Index(decoded, ":")
				if colonIdx != -1 {
					username = decoded[:colonIdx]
					password = decoded[colonIdx+1:]
				} else {
					username = decoded
				}
			}
		}

		// Parse server:port (support IPv6)
		if strings.HasPrefix(serverPart, "[") {
			closeBracket := strings.Index(serverPart, "]")
			if closeBracket != -1 {
				server = serverPart[1:closeBracket]
				portPart := serverPart[closeBracket+1:]
				port, _ = strconv.Atoi(strings.TrimPrefix(portPart, ":"))
			}
		} else {
			lastColon := strings.LastIndex(serverPart, ":")
			if lastColon != -1 {
				server = serverPart[:lastColon]
				port, _ = strconv.Atoi(serverPart[lastColon+1:])
			} else {
				server = serverPart
			}
		}
	}

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	node := map[string]any{
		"name":   name,
		"type":   "socks5",
		"server": server,
		"port":   port,
		"udp":    true,
	}
	if username != "" {
		node["username"] = username
	}
	if password != "" {
		node["password"] = password
	}

	return node, nil
}

// parseTrojanURL parses trojan:// URL
func parseTrojanURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "trojan://")
	name := "Trojan Node"
	mainPart := content

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Extract query params
	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	// Parse password@server:port
	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid trojan url: missing @")
	}

	password := mainPart[:atIdx]
	serverPart := mainPart[atIdx+1:]

	server, port := parseServerPortWithDefault(serverPart, 443)

	node := map[string]any{
		"name":     name,
		"type":     "trojan",
		"server":   server,
		"port":     port,
		"password": password,
		"udp":      true,
		"tls":      true, // Trojan 默认启用 TLS
	}

	// SNI (支持显式空字符串)
	if sni, ok := queryParams["sni"]; ok {
		node["sni"] = safeDecodeURIComponent(sni)
	} else if peer, ok := queryParams["peer"]; ok {
		node["sni"] = safeDecodeURIComponent(peer)
	} else if host, ok := queryParams["host"]; ok {
		node["sni"] = safeDecodeURIComponent(host)
	}

	// Network
	network := queryParams["type"]
	if network == "" {
		network = "tcp"
	}
	node["network"] = network

	// Transport options
	if network == "ws" {
		wsOpts := map[string]any{
			"path": safeDecodeURIComponent(queryParams["path"]),
		}
		if wsOpts["path"] == "" {
			wsOpts["path"] = "/"
		}
		if host := queryParams["host"]; host != "" {
			wsOpts["headers"] = map[string]string{"Host": safeDecodeURIComponent(host)}
		} else {
			wsOpts["headers"] = map[string]string{}
		}
		applyWSEarlyData(wsOpts, queryParams)
		node["ws-opts"] = wsOpts
	} else if network == "grpc" {
		node["grpc-opts"] = map[string]any{
			"grpc-service-name": safeDecodeURIComponent(queryParams["serviceName"]),
		}
	} else if network == "h2" || network == "http" {
		h2Opts := map[string]any{
			"path": safeDecodeURIComponent(queryParams["path"]),
		}
		if h2Opts["path"] == "" {
			h2Opts["path"] = "/"
		}
		if host := queryParams["host"]; host != "" {
			h2Opts["host"] = []string{safeDecodeURIComponent(host)}
		} else {
			h2Opts["host"] = []string{}
		}
		node["h2-opts"] = h2Opts
	}
	applyTlsSniFallback(node, "sni")

	// ALPN
	if alpn := queryParams["alpn"]; alpn != "" {
		node["alpn"] = strings.Split(alpn, ",")
	}

	// Fingerprint
	if fp := queryParams["fp"]; fp != "" {
		node["client-fingerprint"] = fp
	}

	// Skip cert verify
	scv, _ := skipCertVerify(queryParams)
	node["skip-cert-verify"] = scv

	return node, nil
}

// parseVlessURL parses vless:// URL
func parseVlessURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "vless://")
	name := "VLESS Node"
	mainPart := content

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Extract query params
	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	// Parse uuid@server:port
	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid vless url: missing @")
	}

	uuid := mainPart[:atIdx]
	serverPart := mainPart[atIdx+1:]

	server, port := parseServerPortWithDefault(serverPart, 443)

	security := queryParams["security"]
	if security == "" {
		security = "none"
	}

	encryption := queryParams["encryption"]
	if encryption == "" {
		encryption = "none"
	}

	node := map[string]any{
		"name":       name,
		"type":       "vless",
		"server":     server,
		"port":       port,
		"uuid":       uuid,
		"udp":        true,
		"tls":        security == "tls" || security == "reality",
		"flow":       queryParams["flow"],
		"encryption": encryption,
	}

	// Network
	network := queryParams["type"]
	if network == "" {
		network = "tcp"
	}
	node["network"] = network

	// SNI/Servername (支持显式空字符串)
	if sni, ok := queryParams["sni"]; ok {
		node["servername"] = safeDecodeURIComponent(sni)
	}

	// Skip cert verify（统一别名）
	scv, _ := skipCertVerify(queryParams)
	node["skip-cert-verify"] = scv

	// Reality
	if security == "reality" {
		node["skip-cert-verify"] = true
		realityOpts := map[string]any{}
		if pbk := firstNonEmpty(queryParams, "pbk", "public-key"); pbk != "" {
			realityOpts["public-key"] = pbk
		}
		if sid := queryParams["sid"]; sid != "" {
			realityOpts["short-id"] = sid
		} else {
			realityOpts["short-id"] = ""
		}
		if spx := firstNonEmpty(queryParams, "spx", "spider-x"); spx != "" {
			realityOpts["spider-x"] = spx
		}
		node["reality-opts"] = realityOpts
		if fp := queryParams["fp"]; fp != "" {
			node["client-fingerprint"] = fp
		}
	}

	// Transport options
	if network == "ws" {
		wsOpts := map[string]any{
			"path": safeDecodeURIComponent(queryParams["path"]),
		}
		if wsOpts["path"] == "" {
			wsOpts["path"] = "/"
		}
		if host := queryParams["host"]; host != "" {
			wsOpts["headers"] = map[string]string{"Host": safeDecodeURIComponent(host)}
		} else {
			wsOpts["headers"] = map[string]string{}
		}
		applyWSEarlyData(wsOpts, queryParams)
		node["ws-opts"] = wsOpts
	} else if network == "grpc" {
		serviceName := queryParams["serviceName"]
		if serviceName == "" {
			serviceName = queryParams["path"]
		}
		node["grpc-opts"] = map[string]any{
			"grpc-service-name": safeDecodeURIComponent(serviceName),
		}
	} else if network == "h2" || network == "http" {
		h2Opts := map[string]any{
			"path": safeDecodeURIComponent(queryParams["path"]),
		}
		if h2Opts["path"] == "" {
			h2Opts["path"] = "/"
		}
		if host := queryParams["host"]; host != "" {
			h2Opts["host"] = []string{safeDecodeURIComponent(host)}
		} else {
			h2Opts["host"] = []string{}
		}
		node["h2-opts"] = h2Opts
	} else if network == "xhttp" {
		node["network"] = "xhttp"
		xhttpOpts := map[string]any{
			"path": safeDecodeURIComponent(queryParams["path"]),
		}
		if xhttpOpts["path"] == "" {
			xhttpOpts["path"] = "/"
		}
		if host := queryParams["host"]; host != "" {
			xhttpOpts["headers"] = map[string]string{"Host": safeDecodeURIComponent(host)}
		} else {
			xhttpOpts["headers"] = map[string]string{}
		}
		node["xhttp-opts"] = xhttpOpts
		if mode := queryParams["mode"]; mode != "" {
			node["mode"] = mode
		} else {
			node["mode"] = "auto"
		}
	}
	applyTlsSniFallback(node, "servername")
	if _, exists := node["servername"]; !exists {
		if tlsEnabled, ok := node["tls"].(bool); !ok || !tlsEnabled {
			node["servername"] = server
		}
	}

	// ALPN
	if alpn := queryParams["alpn"]; alpn != "" {
		node["alpn"] = strings.Split(alpn, ",")
	}

	// headerType
	if headerType := queryParams["headerType"]; headerType != "" {
		node["headerType"] = headerType
	}

	return node, nil
}

// parseHysteriaURL parses hysteria:// URL
func parseHysteriaURL(uri string) (map[string]any, error) {
	return parseHysteriaGeneric(uri, "hysteria")
}

// parseHysteria2URL parses hysteria2:// or hy2:// URL
func parseHysteria2URL(uri string) (map[string]any, error) {
	uri = strings.Replace(uri, "hy2://", "hysteria2://", 1)
	return parseHysteriaGeneric(uri, "hysteria2")
}

// parseHysteriaGeneric parses hysteria or hysteria2 URL
func parseHysteriaGeneric(uri string, protocol string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, protocol+"://")
	name := protocol + " Node"
	mainPart := content

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Extract query params
	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	// Parse password@server:port
	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid %s url: missing @", protocol)
	}

	password := safeDecodeURIComponent(mainPart[:atIdx])
	serverPart := mainPart[atIdx+1:]

	server, port := parseServerPortWithDefault(serverPart, 0)

	node := map[string]any{
		"name":     name,
		"type":     protocol,
		"server":   server,
		"port":     port,
		"password": password,
		"udp":      true,
	}

	// SNI (支持显式空字符串)
	if sni, ok := queryParams["sni"]; ok {
		node["sni"] = safeDecodeURIComponent(sni)
	} else if peer, ok := queryParams["peer"]; ok {
		node["sni"] = safeDecodeURIComponent(peer)
	}

	// OBFS
	if obfs := queryParams["obfs"]; obfs != "" {
		node["obfs"] = obfs
		if obfsPassword := queryParams["obfs-password"]; obfsPassword != "" {
			node["obfs-password"] = obfsPassword
		} else if obfsParam := queryParams["obfsParam"]; obfsParam != "" {
			node["obfs-password"] = obfsParam
		}
	}

	// ALPN
	if alpn := queryParams["alpn"]; alpn != "" {
		node["alpn"] = strings.Split(alpn, ",")
	}

	// Skip cert verify
	scv, _ := skipCertVerify(queryParams)
	node["skip-cert-verify"] = scv

	// Client fingerprint
	if fp := queryParams["fp"]; fp != "" {
		node["client-fingerprint"] = fp
	}

	// Bandwidth
	if up := queryParams["up"]; up != "" {
		node["up"] = up
	} else if upmbps := queryParams["upmbps"]; upmbps != "" {
		node["up"] = upmbps
	}
	if down := queryParams["down"]; down != "" {
		node["down"] = down
	} else if downmbps := queryParams["downmbps"]; downmbps != "" {
		node["down"] = downmbps
	}

	// Port hopping（mport / ports 别名）
	if ports := firstNonEmpty(queryParams, "mport", "ports"); ports != "" {
		node["ports"] = ports
	}
	// 端口跳跃间隔
	if hi := firstNonEmpty(queryParams, "hop-interval", "hopInterval"); hi != "" {
		if n, err := strconv.Atoi(hi); err == nil {
			node["hop-interval"] = n
		}
	}
	// 证书 PIN（pinSHA256 → tls-fingerprint）：下游 substore producer 统一从 tls-fingerprint 读取
	// （clash/clashmeta 再转 mihomo 的 fingerprint，loon 直接读 tls-fingerprint）。
	if pin := firstNonEmpty(queryParams, "pinSHA256", "pinsha256"); pin != "" {
		node["tls-fingerprint"] = pin
	}

	applyTlsSniFallback(node, "sni")

	return node, nil
}

// parseTuicURL parses tuic:// URL
func parseTuicURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "tuic://")
	name := "TUIC Node"
	mainPart := content

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Extract query params
	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	// Parse uuid:password@server:port
	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid tuic url: missing @")
	}

	authPart := safeDecodeURIComponent(mainPart[:atIdx])
	serverPart := mainPart[atIdx+1:]

	var uuid, password string
	colonIdx := strings.Index(authPart, ":")
	if colonIdx != -1 {
		uuid = authPart[:colonIdx]
		password = authPart[colonIdx+1:]
	} else {
		uuid = authPart
		password = queryParams["password"]
	}

	server, port := parseServerPortWithDefault(serverPart, 0)

	node := map[string]any{
		"name":     name,
		"type":     "tuic",
		"server":   server,
		"port":     port,
		"uuid":     uuid,
		"password": password,
		"udp":      true,
	}

	// SNI (支持显式空字符串)
	if sni, ok := queryParams["sni"]; ok {
		node["sni"] = safeDecodeURIComponent(sni)
	}
	applyTlsSniFallback(node, "sni")

	// ALPN
	if alpn := queryParams["alpn"]; alpn != "" {
		node["alpn"] = strings.Split(alpn, ",")
	} else {
		node["alpn"] = []string{"h3"}
	}

	// Skip cert verify
	scv, _ := skipCertVerify(queryParams)
	node["skip-cert-verify"] = scv

	// Congestion controller
	if cc := queryParams["congestion_control"]; cc != "" {
		node["congestion-controller"] = cc
	} else {
		node["congestion-controller"] = "bbr"
	}

	// UDP relay mode
	if urm := queryParams["udp_relay_mode"]; urm != "" {
		node["udp-relay-mode"] = urm
	} else {
		node["udp-relay-mode"] = "native"
	}

	// TUIC 布尔特性（命中才写，支持下划线/连字符两种 key 名）
	if v, ok := boolFromAliases(queryParams, "disable_sni", "disable-sni"); ok {
		node["disable-sni"] = v
	}
	if v, ok := boolFromAliases(queryParams, "fast_open", "fast-open"); ok {
		node["fast-open"] = v
	}
	if v, ok := boolFromAliases(queryParams, "reduce_rtt", "reduce-rtt"); ok {
		node["reduce-rtt"] = v
	}
	if v, ok := boolFromAliases(queryParams, "udp_over_stream", "udp-over-stream"); ok {
		node["udp-over-stream"] = v
	}

	return node, nil
}

// parseAnytlsURL parses anytls:// URL
func parseAnytlsURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "anytls://")
	name := "AnyTLS Node"
	mainPart := content

	// Extract name
	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	// Extract query params
	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	// Parse password@server:port
	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid anytls url: missing @")
	}

	password := mainPart[:atIdx]
	serverPart := mainPart[atIdx+1:]

	server, port := parseServerPortWithDefault(serverPart, 443)

	node := map[string]any{
		"name":     name,
		"type":     "anytls",
		"server":   server,
		"port":     port,
		"password": password,
		"udp":      true,
	}

	// SNI (支持显式空字符串)
	if sni, ok := queryParams["sni"]; ok {
		node["sni"] = safeDecodeURIComponent(sni)
	} else if peer, ok := queryParams["peer"]; ok {
		node["sni"] = safeDecodeURIComponent(peer)
	}
	applyTlsSniFallback(node, "sni")

	// ALPN
	if alpn := queryParams["alpn"]; alpn != "" {
		node["alpn"] = strings.Split(alpn, ",")
	}

	// Skip cert verify
	scv, _ := skipCertVerify(queryParams)
	node["skip-cert-verify"] = scv

	// Client fingerprint
	if fp := queryParams["fp"]; fp != "" {
		node["client-fingerprint"] = fp
	}

	// AnyTLS specific options
	if v := queryParams["idleSessionCheckInterval"]; v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			node["idle-session-check-interval"] = i
		}
	}
	if v := queryParams["idleSessionTimeout"]; v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			node["idle-session-timeout"] = i
		}
	}
	if v := queryParams["minIdleSession"]; v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			node["min-idle-session"] = i
		}
	}

	return node, nil
}

// parseWireGuardURL parses wireguard:// or wg:// URL
func parseWireGuardURL(uri string) (map[string]any, error) {
	content := regexp.MustCompile(`^(wireguard|wg)://`).ReplaceAllString(uri, "")

	// Parse URL parts with regex
	re := regexp.MustCompile(`^((.*?)@)?(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$`)
	match := re.FindStringSubmatch(content)
	if match == nil {
		return nil, fmt.Errorf("invalid wireguard url")
	}

	privateKey, _ := url.QueryUnescape(match[2])
	server := match[3]
	port := 51820
	if match[5] != "" {
		port, _ = strconv.Atoi(match[5])
	}
	addons := match[7]
	name := match[8]
	if name != "" {
		name, _ = url.QueryUnescape(name)
	} else {
		name = fmt.Sprintf("WireGuard %s:%d", server, port)
	}

	node := map[string]any{
		"type":        "wireguard",
		"name":        name,
		"server":      server,
		"port":        port,
		"private-key": privateKey,
		"udp":         true,
	}

	// Parse addons
	for _, addon := range strings.Split(addons, "&") {
		if addon == "" {
			continue
		}
		kv := strings.SplitN(addon, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(kv[0], "_", "-"))
		value, _ := url.QueryUnescape(kv[1])

		switch key {
		case "reserved":
			parts := strings.Split(value, ",")
			if len(parts) == 3 {
				reserved := make([]int, 3)
				for i, p := range parts {
					reserved[i], _ = strconv.Atoi(strings.TrimSpace(p))
				}
				node["reserved"] = reserved
			}
		case "address", "ip":
			for _, ip := range strings.Split(value, ",") {
				ip = strings.TrimSpace(ip)
				ip = regexp.MustCompile(`/\d+$`).ReplaceAllString(ip, "")
				ip = strings.TrimPrefix(ip, "[")
				ip = strings.TrimSuffix(ip, "]")
				if isIPv4(ip) {
					node["ip"] = ip
				} else if isIPv6(ip) {
					node["ipv6"] = ip
				}
			}
		case "mtu":
			node["mtu"], _ = strconv.Atoi(value)
		case "publickey":
			node["public-key"] = value
		case "privatekey":
			node["private-key"] = value
		case "presharedkey", "preshared-key", "pre-shared-key":
			// 统一写 pre-shared-key（URI 常见无连字符写法 presharedkey 否则会透传成下游不认的 key）
			node["pre-shared-key"] = value
		case "udp":
			node["udp"] = value == "true" || value == "1"
		case "allowed-ips":
			if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
				innerValue := value[1 : len(value)-1]
				parts := strings.Split(innerValue, ",")
				var ips []string
				for _, p := range parts {
					p = strings.TrimSpace(p)
					if p != "" {
						ips = append(ips, p)
					}
				}
				node["allowed-ips"] = ips
			} else {
				node["allowed-ips"] = value
			}
		default:
			if key != "name" && key != "type" && key != "server" && key != "port" && key != "private-key" && key != "flag" {
				node[key] = value
			}
		}
	}

	return node, nil
}

// parseHTTPURL parses http:// or https:// proxy URL
func parseHTTPURL(uri string) (map[string]any, error) {
	isTLS := strings.HasPrefix(uri, "https://")
	content := uri
	if isTLS {
		content = strings.TrimPrefix(uri, "https://")
	} else {
		content = strings.TrimPrefix(uri, "http://")
	}

	name := ""
	mainPart := content

	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	if idx := strings.Index(mainPart, "?"); idx != -1 {
		mainPart = mainPart[:idx]
	}

	var username, password string
	var serverPart string

	if atIdx := strings.LastIndex(mainPart, "@"); atIdx != -1 {
		authPart := mainPart[:atIdx]
		serverPart = mainPart[atIdx+1:]
		if colonIdx := strings.Index(authPart, ":"); colonIdx != -1 {
			username, _ = url.QueryUnescape(authPart[:colonIdx])
			password, _ = url.QueryUnescape(authPart[colonIdx+1:])
		} else {
			username, _ = url.QueryUnescape(authPart)
		}
	} else {
		serverPart = mainPart
	}

	defaultPort := 80
	if isTLS {
		defaultPort = 443
	}
	server, port := parseServerPortWithDefault(serverPart, defaultPort)

	if name == "" {
		name = fmt.Sprintf("%s:%d", server, port)
	}

	node := map[string]any{
		"name":     name,
		"type":     "http",
		"server":   server,
		"port":     port,
		"username": username,
		"password": password,
	}
	if isTLS {
		node["tls"] = true
	}
	return node, nil
}

// parseNaiveURL parses naive+https:// or naive:// URL
func parseNaiveURL(uri string) (map[string]any, error) {
	content := regexp.MustCompile(`^naive(\+https?)?://`).ReplaceAllString(uri, "")
	name := "Naive Node"
	mainPart := content

	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid naive url: missing @")
	}

	authPart := mainPart[:atIdx]
	serverPart := mainPart[atIdx+1:]
	server, port := parseServerPortWithDefault(serverPart, 443)

	var username, password string
	if colonIdx := strings.Index(authPart, ":"); colonIdx != -1 {
		username, _ = url.QueryUnescape(authPart[:colonIdx])
		password, _ = url.QueryUnescape(authPart[colonIdx+1:])
	} else {
		username, _ = url.QueryUnescape(authPart)
	}

	node := map[string]any{
		"name":     name,
		"type":     "naive",
		"server":   server,
		"port":     port,
		"username": username,
		"password": password,
	}

	if sni := queryParams["sni"]; sni != "" {
		node["sni"] = safeDecodeURIComponent(sni)
	}
	if queryParams["uot"] == "1" {
		node["udp-over-tcp"] = true
	}
	// HTTP 头（header=key:value → extra-headers，取自 proxy_provider_serve 实现）
	if header := queryParams["header"]; header != "" {
		if idx := strings.Index(header, ":"); idx != -1 {
			key := strings.TrimSpace(header[:idx])
			val := strings.TrimSpace(header[idx+1:])
			node["extra-headers"] = map[string]any{key: val}
		}
	}

	return node, nil
}

// parseMieruURL parses mieru:// URL
func parseMieruURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "mieru://")
	name := "Mieru Node"
	mainPart := content

	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}
	mainPart = strings.TrimSuffix(mainPart, "/")

	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid mieru url: missing @")
	}

	authPart, _ := url.QueryUnescape(mainPart[:atIdx])
	serverPart := mainPart[atIdx+1:]
	server, port := parseServerPortWithDefault(serverPart, 0)

	var username, password string
	if colonIdx := strings.Index(authPart, ":"); colonIdx != -1 {
		username = authPart[:colonIdx]
		password = authPart[colonIdx+1:]
	} else {
		username = authPart
	}

	node := map[string]any{
		"name":     name,
		"type":     "mieru",
		"server":   server,
		"port":     port,
		"username": username,
		"password": password,
	}

	if v := queryParams["transport"]; v != "" {
		node["transport"] = v
	} else if v := queryParams["handshake-mode"]; v != "" {
		node["transport"] = v
	} else {
		node["transport"] = "TCP"
	}

	if v := queryParams["multiplexing"]; v != "" {
		node["multiplexing"] = v
	} else {
		node["multiplexing"] = "MULTIPLEXING_LOW"
	}

	if v := queryParams["mtu"]; v != "" {
		if mtu, err := strconv.Atoi(v); err == nil {
			node["mtu"] = mtu
		}
	}
	if v := queryParams["port-range"]; v != "" {
		node["port-range"] = v
	}
	if v := queryParams["traffic-pattern"]; v != "" {
		node["traffic-pattern"] = v
	}

	return node, nil
}

func parseSnellURL(uri string) (map[string]any, error) {
	content := strings.TrimPrefix(uri, "snell://")
	name := "Snell Node"
	mainPart := content

	if idx := strings.LastIndex(content, "#"); idx != -1 {
		mainPart = content[:idx]
		name, _ = url.QueryUnescape(content[idx+1:])
	}

	var queryParams map[string]string
	if idx := strings.Index(mainPart, "?"); idx != -1 {
		queryParams = parseQueryParams(mainPart[idx+1:])
		mainPart = mainPart[:idx]
	}

	atIdx := strings.LastIndex(mainPart, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid snell url: missing @")
	}

	password := mainPart[:atIdx]
	serverPart := mainPart[atIdx+1:]
	server, port := parseServerPortWithDefault(serverPart, 0)

	node := map[string]any{
		"name":   name,
		"type":   "snell",
		"server": server,
		"port":   port,
		"psk":    password,
	}

	if v := queryParams["version"]; v != "" {
		if ver, err := strconv.Atoi(v); err == nil {
			node["version"] = ver
		}
	} else {
		node["version"] = 4
	}

	if obfs := queryParams["obfs"]; obfs != "" && obfs != "none" {
		obfsOpts := map[string]any{"mode": obfs}
		if host := queryParams["obfs-host"]; host != "" {
			obfsOpts["host"] = host
		} else if host := queryParams["obfs-hostname"]; host != "" {
			obfsOpts["host"] = host
		}
		node["obfs-opts"] = obfsOpts
	}

	return node, nil
}

// Parse parses a single proxy URL and returns Clash format
func Parse(uri string) (map[string]any, error) {
	uri = strings.TrimSpace(uri)

	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return parseVmessURL(uri)
	case strings.HasPrefix(uri, "ssr://"):
		return parseShadowsocksRURL(uri)
	case strings.HasPrefix(uri, "ss://"):
		return parseShadowsocksURL(uri)
	case strings.HasPrefix(uri, "socks://"), strings.HasPrefix(uri, "socks5://"):
		return parseSocksURL(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return parseTrojanURL(uri)
	case strings.HasPrefix(uri, "vless://"):
		return parseVlessURL(uri)
	case strings.HasPrefix(uri, "hysteria://"):
		return parseHysteriaURL(uri)
	case strings.HasPrefix(uri, "hy2://"), strings.HasPrefix(uri, "hysteria2://"):
		return parseHysteria2URL(uri)
	case strings.HasPrefix(uri, "tuic://"):
		return parseTuicURL(uri)
	case strings.HasPrefix(uri, "anytls://"):
		return parseAnytlsURL(uri)
	case strings.HasPrefix(uri, "wireguard://"), strings.HasPrefix(uri, "wg://"):
		return parseWireGuardURL(uri)
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		return parseHTTPURL(uri)
	case strings.HasPrefix(uri, "naive://"), strings.HasPrefix(uri, "naive+https://"), strings.HasPrefix(uri, "naive+http://"):
		return parseNaiveURL(uri)
	case strings.HasPrefix(uri, "mieru://"):
		return parseMieruURL(uri)
	case strings.HasPrefix(uri, "snell://"):
		return parseSnellURL(uri)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", uri)
	}
}

// ParseSubscription parses v2ray format subscription content (base64 encoded URIs)
// Returns a list of Clash format proxies
func ParseSubscription(content string) ([]map[string]any, error) {
	// Try to decode base64
	decoded, err := base64DecodeURLSafe(content)
	if err != nil || !strings.Contains(decoded, "://") {
		// If decoding fails or doesn't look like URIs, assume it's already plain text
		decoded = content
	}

	// Split by newlines
	lines := strings.Split(decoded, "\n")
	var proxies []map[string]any

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "://") {
			proxy, err := Parse(line)
			if err != nil {
				continue
			}
			proxies = append(proxies, proxy)
			continue
		}

		// 非 URI 行尝试按 Surge INI 行解析(目前仅 snell)
		if node := parseSurgeLine(line); node != nil {
			proxies = append(proxies, node)
		}
	}

	return proxies, nil
}

// Helper functions
// applyWSEarlyData 把独立的 ed query 参数写入 ws-opts 的 early-data 字段。
// path 内嵌的 ?ed= 由下游 producer 从 path 自行提取，这里只补独立的 ed / eh 参数。
func applyWSEarlyData(wsOpts map[string]any, params map[string]string) {
	ed := params["ed"]
	if ed == "" {
		return
	}
	if n, err := strconv.Atoi(ed); err == nil && n > 0 {
		wsOpts["max-early-data"] = n
		hdr := params["eh"]
		if hdr == "" {
			hdr = "Sec-WebSocket-Protocol"
		}
		wsOpts["early-data-header-name"] = hdr
	}
}

func getString(m map[string]any, key string, defaultVal string) string {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return strconv.FormatFloat(val, 'f', -1, 64)
		case int:
			return strconv.Itoa(val)
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return defaultVal
}

func getInt(m map[string]any, key string, defaultVal int) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		case string:
			if i, err := strconv.Atoi(val); err == nil {
				return i
			}
		}
	}
	return defaultVal
}

func parseServerPortWithDefault(serverPart string, defaultPort int) (string, int) {
	var server string
	var port int

	if strings.HasPrefix(serverPart, "[") {
		// IPv6
		closeBracket := strings.Index(serverPart, "]")
		if closeBracket != -1 {
			server = serverPart[1:closeBracket]
			portPart := serverPart[closeBracket+1:]
			if strings.HasPrefix(portPart, ":") {
				port, _ = strconv.Atoi(portPart[1:])
			}
		}
	} else {
		parts := strings.Split(serverPart, ":")
		server = parts[0]
		if len(parts) > 1 {
			port, _ = strconv.Atoi(parts[1])
		}
	}

	if port == 0 {
		port = defaultPort
	}

	return server, port
}

func isIPv4(s string) bool {
	re := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !re.MatchString(s) {
		return false
	}
	parts := strings.Split(s, ".")
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		if n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(s string) bool {
	re := regexp.MustCompile(`^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$`)
	return re.MatchString(s) ||
		regexp.MustCompile(`^::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$`).MatchString(s) ||
		regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){1,6}:$`).MatchString(s) ||
		s == "::"
}

func isIP(s string) bool {
	normalized := strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return isIPv4(normalized) || isIPv6(normalized)
}
