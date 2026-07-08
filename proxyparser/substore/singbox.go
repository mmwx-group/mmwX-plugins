package substore

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SingboxProducer implements the Producer interface for sing-box format
type SingboxProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewSingboxProducer creates a new sing-box producer
func NewSingboxProducer() *SingboxProducer {
	return &SingboxProducer{
		producerType: "sing-box",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *SingboxProducer) GetType() string {
	return p.producerType
}

// IP version mapping for sing-box
var singboxIPVersions = map[string]string{
	"ipv4":        "ipv4_only",
	"ipv6":        "ipv6_only",
	"v4-only":     "ipv4_only",
	"v6-only":     "ipv6_only",
	"ipv4-prefer": "prefer_ipv4",
	"ipv6-prefer": "prefer_ipv6",
	"prefer-v4":   "prefer_ipv4",
	"prefer-v6":   "prefer_ipv6",
}

// Produce converts proxies to sing-box format
func (p *SingboxProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	// First, convert proxies to ClashMeta format (internal)
	clashMetaProducer := NewClashMetaProducer()
	clashProxies, err := clashMetaProducer.Produce(proxies, "internal", &ProduceOptions{
		IncludeUnsupportedProxy: true,
	})
	if err != nil {
		return nil, err
	}

	proxiesSlice, ok := clashProxies.([]Proxy)
	if !ok {
		return nil, fmt.Errorf("unexpected type from ClashMeta producer")
	}

	list := make([]map[string]interface{}, 0)

	for _, proxy := range proxiesSlice {
		proxyType := p.helper.GetProxyType(proxy)
		var parsed map[string]interface{}
		var err error

		if GetString(proxy, "network") == "xhttp" {
			continue
		}

		switch proxyType {
		case "ssh":
			parsed, err = p.sshParser(proxy)
		case "http":
			parsed, err = p.httpParser(proxy)
		case "socks5":
			if GetBool(proxy, "tls") {
				err = fmt.Errorf("platform sing-box does not support proxy type: %s with tls", proxyType)
			} else {
				parsed, err = p.socks5Parser(proxy)
			}
		case "ss":
			if GetString(proxy, "plugin") == "shadow-tls" {
				ssPart, stPart, err2 := p.shadowTLSParser(proxy)
				if err2 == nil {
					p.passthroughExtraFields(proxy, ssPart)
					p.passthroughExtraFields(proxy, stPart)
					list = append(list, ssPart)
					list = append(list, stPart)
				}
				err = err2
			} else {
				parsed, err = p.ssParser(proxy)
			}
		case "ssr":
			if opts.IncludeUnsupportedProxy {
				parsed, err = p.ssrParser(proxy)
			} else {
				err = fmt.Errorf("platform sing-box does not support proxy type: %s", proxyType)
			}
		case "vmess":
			network := GetString(proxy, "network")
			if network == "" || network == "ws" || network == "grpc" || network == "h2" || network == "http" {
				parsed, err = p.vmessParser(proxy)
			} else {
				err = fmt.Errorf("platform sing-box does not support proxy type: %s with network %s", proxyType, network)
			}
		case "vless":
			encryption := GetString(proxy, "encryption")
			if encryption != "" && encryption != "none" {
				err = fmt.Errorf("VLESS encryption is not supported")
			} else {
				flow := GetString(proxy, "flow")
				if flow == "" || flow == "xtls-rprx-vision" {
					parsed, err = p.vlessParser(proxy)
				} else {
					err = fmt.Errorf("platform sing-box does not support proxy type: %s with flow %s", proxyType, flow)
				}
			}
		case "trojan":
			if GetString(proxy, "flow") == "" {
				parsed, err = p.trojanParser(proxy)
			} else {
				err = fmt.Errorf("platform sing-box does not support proxy type: %s with flow %s", proxyType, GetString(proxy, "flow"))
			}
		case "hysteria":
			parsed, err = p.hysteriaParser(proxy)
		case "hysteria2":
			parsed, err = p.hysteria2Parser(proxy)
		case "tuic":
			if GetString(proxy, "token") == "" {
				parsed, err = p.tuic5Parser(proxy)
			} else {
				err = fmt.Errorf("platform sing-box does not support proxy type: TUIC v4")
			}
		case "wireguard":
			parsed, err = p.wireguardParser(proxy)
		case "anytls":
			parsed, err = p.anytlsParser(proxy)
		case "snell":
			parsed, err = p.snellParser(proxy)
		case "naive":
			parsed, err = p.naiveParser(proxy)
		default:
			err = fmt.Errorf("platform sing-box does not support proxy type: %s", proxyType)
		}

		if err != nil {
			// Skip this proxy if there's an error and we're not including unsupported
			continue
		}

		if parsed != nil {
			p.passthroughExtraFields(proxy, parsed)
			list = append(list, parsed)
		}
	}

	if outputType == "internal" {
		return list, nil
	}

	outbounds := make([]map[string]interface{}, 0)
	endpoints := make([]map[string]interface{}, 0)
	for _, item := range list {
		itemType, _ := item["type"].(string)
		if itemType == "wireguard" || itemType == "tailscale" {
			endpoints = append(endpoints, item)
		} else {
			outbounds = append(outbounds, item)
		}
	}

	result := map[string]interface{}{
		"outbounds": outbounds,
		"endpoints": endpoints,
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}

	return string(jsonBytes), nil
}

// Helper parsers

func (p *SingboxProducer) ipVersionParser(proxy Proxy, parsed map[string]interface{}) {
	ipVersion := GetString(proxy, "ip-version")
	dnsServer := GetString(proxy, "_dns_server")
	strategy, ok := singboxIPVersions[ipVersion]

	if dnsServer != "" && ok {
		parsed["domain_resolver"] = map[string]interface{}{
			"server":   dnsServer,
			"strategy": strategy,
		}
	}
}

func (p *SingboxProducer) domainResolverParser(proxy Proxy, parsed map[string]interface{}) {
	if dr := GetMap(proxy, "_domain_resolver"); dr != nil {
		existing, _ := parsed["domain_resolver"].(map[string]interface{})
		if existing == nil {
			existing = make(map[string]interface{})
		}
		for k, v := range dr {
			existing[k] = v
		}
		parsed["domain_resolver"] = existing
	}
}

func (p *SingboxProducer) detourParser(proxy Proxy, parsed map[string]interface{}) {
	dialerProxy := GetString(proxy, "dialer-proxy")
	if dialerProxy == "" {
		dialerProxy = GetString(proxy, "detour")
	}
	if dialerProxy != "" {
		parsed["detour"] = dialerProxy
	}
}

func (p *SingboxProducer) networkParser(proxy Proxy, parsed map[string]interface{}) {
	network := GetString(proxy, "_network")
	if network == "tcp" || network == "udp" {
		parsed["network"] = network
	}
}

func (p *SingboxProducer) tfoParser(proxy Proxy, parsed map[string]interface{}) {
	if GetBool(proxy, "tfo") || GetBool(proxy, "tcp_fast_open") || GetBool(proxy, "tcp-fast-open") {
		parsed["tcp_fast_open"] = true
	}
}

// singboxConsumedKeys are standard Clash proxy fields already handled by specific parsers.
var singboxConsumedKeys = map[string]bool{
	"name": true, "type": true, "server": true, "port": true,
	"password": true, "uuid": true, "cipher": true, "alterId": true,
	"network": true, "tls": true, "skip-cert-verify": true,
	"servername": true, "sni": true, "alpn": true,
	"ws-opts": true, "grpc-opts": true, "h2-opts": true, "http-opts": true,
	"reality-opts": true, "client-fingerprint": true, "fingerprint": true,
	"flow": true, "udp": true, "xudp": true,
	"fast-open": true, "tfo": true, "tcp-fast-open": true, "tcp_fast_open": true,
	"smux": true, "ip-version": true,
	"dialer-proxy": true, "detour": true,
	"_dns_server": true, "_network": true,
	"plugin": true, "plugin-opts": true,
	"obfs": true, "obfs-param": true, "protocol": true, "protocol-param": true,
	"obfs-opts": true, "reuse": true, "_userkey": true, "psk": true,
	"up": true, "down": true,
	"auth": true, "auth-str": true, "auth_str": true,
	"ca": true, "ca-str": true, "ca_str": true,
	"recv-window-conn": true, "recv-window": true, "recv_window_conn": true, "recv_window": true,
	"disable-mtu-discovery": true,
	"obfs-password": true, "ports": true, "hop-interval": true,
	"congestion-controller": true, "udp-relay-mode": true,
	"reduce-rtt": true, "heartbeat-interval": true,
	"ip": true, "ipv6": true, "public-key": true, "private-key": true,
	"pre-shared-key": true, "reserved": true, "mtu": true,
	"allowed-ips": true, "peers": true, "remote-dns-resolve": true, "dns": true,
	"username": true, "host-key": true, "host-key-algorithms": true,
	"private-key-passphrase": true, "private-key-path": true,
	"headers": true, "path": true,
	"version": true, "token": true,
	"idle-timeout": true, "padding": true,
	"encryption": true,
	"udp-over-tcp": true, "udp-over-tcp-version": true,
	"insecure": true, "peer": true, "disable-sni": true,
	"ech-opts": true, "server-fingerprint": true,
	"udp-over-stream": true, "udp-timeout": true,
	"insecure-concurrency": true, "extra-headers": true,
	"idle-session-check-interval": true, "idle-session-timeout": true, "min-idle-session": true,
	"system": true, "workers": true,
	"ws-headers": true, "ws-path": true, "ws-host": true,
	"http-host": true, "http-path": true, "h2-host": true, "h2-path": true,
	"obfs-host": true,
}

func (p *SingboxProducer) passthroughExtraFields(proxy Proxy, parsed map[string]interface{}) {
	for key, value := range proxy {
		if singboxConsumedKeys[key] {
			continue
		}
		sbKey := strings.ReplaceAll(key, "-", "_")
		if _, exists := parsed[sbKey]; exists {
			continue
		}
		parsed[sbKey] = value
	}
}

func (p *SingboxProducer) smuxParser(proxy Proxy, parsed map[string]interface{}) {
	smux := GetMap(proxy, "smux")
	if smux == nil || !GetBool(smux, "enabled") {
		return
	}

	multiplex := map[string]interface{}{
		"enabled": true,
	}

	if protocol := GetString(smux, "protocol"); protocol != "" {
		multiplex["protocol"] = protocol
	}

	if maxConn := GetInt(smux, "max-connections"); maxConn > 0 {
		multiplex["max_connections"] = maxConn
	}

	if maxStreams := GetInt(smux, "max-streams"); maxStreams > 0 {
		multiplex["max_streams"] = maxStreams
	}

	if minStreams := GetInt(smux, "min-streams"); minStreams > 0 {
		multiplex["min_streams"] = minStreams
	}

	if GetBool(smux, "padding") {
		multiplex["padding"] = true
	}

	brutalOpts := GetMap(smux, "brutal-opts")
	if brutalOpts != nil {
		up := GetInt(brutalOpts, "up")
		down := GetInt(brutalOpts, "down")
		if up > 0 || down > 0 {
			brutal := map[string]interface{}{
				"enabled": true,
			}
			if up > 0 {
				brutal["up_mbps"] = up
			}
			if down > 0 {
				brutal["down_mbps"] = down
			}
			multiplex["brutal"] = brutal
		}
	}

	parsed["multiplex"] = multiplex
}

func (p *SingboxProducer) wsParser(proxy Proxy, parsed map[string]interface{}) {
	transport := map[string]interface{}{
		"type":    "ws",
		"headers": make(map[string]interface{}),
	}

	// Handle ws-opts
	wsOpts := GetMap(proxy, "ws-opts")
	if wsOpts != nil {
		if path := GetString(wsOpts, "path"); path != "" {
			transport["path"] = path
		}

		if earlyDataHeader := GetString(wsOpts, "early-data-header-name"); earlyDataHeader != "" {
			transport["early_data_header_name"] = earlyDataHeader
		}

		if maxEarlyData := GetInt(wsOpts, "max-early-data"); maxEarlyData > 0 {
			transport["max_early_data"] = maxEarlyData
		}

		headers := GetMap(wsOpts, "headers")
		if headers != nil {
			processedHeaders := make(map[string]interface{})
			for key, value := range headers {
				if value == "" {
					continue
				}
				var strSlice []string
				if str, ok := value.(string); ok {
					strSlice = []string{str}
				} else if slice, ok := value.([]interface{}); ok {
					for _, v := range slice {
						strSlice = append(strSlice, fmt.Sprintf("%v", v))
					}
				}
				if len(strSlice) > 0 {
					processedHeaders[key] = strSlice
				}
			}

			// Handle Host header specially
			if hostSlice, ok := processedHeaders["Host"].([]string); ok && len(hostSlice) == 1 {
				for _, item := range strings.Split(fmt.Sprintf("Host:%s", hostSlice[0]), "\n") {
					parts := strings.SplitN(item, ":", 2)
					if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
						processedHeaders[strings.TrimSpace(parts[0])] = strings.Split(strings.TrimSpace(parts[1]), ",")
					}
				}
			}

			transport["headers"] = processedHeaders
		}
	}

	// Handle ws-headers
	wsHeaders := GetMap(proxy, "ws-headers")
	if wsHeaders != nil {
		headers, _ := transport["headers"].(map[string]interface{})
		if headers == nil {
			headers = make(map[string]interface{})
		}

		for key, value := range wsHeaders {
			if value == "" {
				continue
			}
			var strSlice []string
			if str, ok := value.(string); ok {
				strSlice = []string{str}
			} else if slice, ok := value.([]interface{}); ok {
				for _, v := range slice {
					strSlice = append(strSlice, fmt.Sprintf("%v", v))
				}
			}
			if len(strSlice) > 0 {
				headers[key] = strSlice
			}
		}

		transport["headers"] = headers
	}

	// Handle ws-path
	if wsPath := GetString(proxy, "ws-path"); wsPath != "" {
		transport["path"] = wsPath
	}

	// Extract early data from path
	if path, ok := transport["path"].(string); ok {
		re := regexp.MustCompile(`^(.*?)(?:\?ed=(\d+))?$`)
		matches := re.FindStringSubmatch(path)
		if len(matches) > 1 {
			transport["path"] = matches[1]
			if len(matches) > 2 && matches[2] != "" {
				transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
				ed, _ := strconv.Atoi(matches[2])
				transport["max_early_data"] = ed
			}
		}
	}

	// Check for HTTP upgrade
	if wsOpts != nil && GetBool(wsOpts, "v2ray-http-upgrade") {
		transport["type"] = "httpupgrade"
		if headers, ok := transport["headers"].(map[string]interface{}); ok {
			if host, exists := headers["Host"]; exists {
				if hostSlice, ok := host.([]string); ok && len(hostSlice) > 0 {
					transport["host"] = hostSlice[0]
				} else if hostStr, ok := host.(string); ok {
					transport["host"] = hostStr
				}
				delete(headers, "Host")
			}
		}
		delete(transport, "max_early_data")
		delete(transport, "early_data_header_name")
	}

	// Simplify single-element arrays to strings
	if headers, ok := transport["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if slice, ok := value.([]string); ok && len(slice) == 1 {
				headers[key] = slice[0]
			}
		}
	}

	parsed["transport"] = transport
}

func (p *SingboxProducer) h1Parser(proxy Proxy, parsed map[string]interface{}) {
	transport := map[string]interface{}{
		"type":    "http",
		"headers": make(map[string]interface{}),
	}

	httpOpts := GetMap(proxy, "http-opts")
	if httpOpts != nil {
		if method := GetString(httpOpts, "method"); method != "" {
			transport["method"] = method
		}

		path := httpOpts["path"]
		if pathSlice, ok := path.([]interface{}); ok && len(pathSlice) > 0 {
			transport["path"] = fmt.Sprintf("%v", pathSlice[0])
		} else if pathStr := GetString(httpOpts, "path"); pathStr != "" {
			transport["path"] = pathStr
		}

		headers := GetMap(httpOpts, "headers")
		if headers != nil {
			processedHeaders := make(map[string]interface{})
			for key, value := range headers {
				if value == "" {
					continue
				}
				if strings.ToLower(key) == "host" {
					var hostSlice []string
					if str, ok := value.(string); ok {
						hostSlice = strings.Split(str, ",")
						for i := range hostSlice {
							hostSlice[i] = strings.TrimSpace(hostSlice[i])
						}
					} else if slice, ok := value.([]interface{}); ok {
						for _, v := range slice {
							hostSlice = append(hostSlice, strings.TrimSpace(fmt.Sprintf("%v", v)))
						}
					}
					if len(hostSlice) > 0 {
						transport["host"] = hostSlice
					}
					continue
				}

				var strSlice []string
				if str, ok := value.(string); ok {
					parts := strings.Split(str, ",")
					for _, part := range parts {
						strSlice = append(strSlice, strings.TrimSpace(part))
					}
				} else if slice, ok := value.([]interface{}); ok {
					for _, v := range slice {
						strSlice = append(strSlice, fmt.Sprintf("%v", v))
					}
				}
				if len(strSlice) > 0 {
					processedHeaders[key] = strSlice
				}
			}
			transport["headers"] = processedHeaders
		}
	}

	if httpHost := proxy["http-host"]; httpHost != nil && httpHost != "" {
		var hostSlice []string
		if str, ok := httpHost.(string); ok {
			parts := strings.Split(str, ",")
			for _, part := range parts {
				hostSlice = append(hostSlice, strings.TrimSpace(part))
			}
		} else if slice, ok := httpHost.([]interface{}); ok {
			for _, v := range slice {
				hostSlice = append(hostSlice, fmt.Sprintf("%v", v))
			}
		}
		if len(hostSlice) > 0 {
			transport["host"] = hostSlice
		}
	}

	if httpPath := proxy["http-path"]; httpPath != nil && httpPath != "" {
		if pathSlice, ok := httpPath.([]interface{}); ok && len(pathSlice) > 0 {
			transport["path"] = fmt.Sprintf("%v", pathSlice[0])
		} else if pathStr, ok := httpPath.(string); ok && pathStr != "" {
			transport["path"] = pathStr
		}
	}

	// Simplify single-element arrays
	if host, ok := transport["host"].([]string); ok && len(host) == 1 {
		transport["host"] = host[0]
	}

	if headers, ok := transport["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if slice, ok := value.([]string); ok && len(slice) == 1 {
				headers[key] = slice[0]
			}
		}
	}

	parsed["transport"] = transport
}

func (p *SingboxProducer) h2Parser(proxy Proxy, parsed map[string]interface{}) {
	transport := map[string]interface{}{
		"type": "http",
	}

	h2Opts := GetMap(proxy, "h2-opts")
	if h2Opts != nil {
		if path := GetString(h2Opts, "path"); path != "" {
			transport["path"] = path
		}

		host := h2Opts["host"]
		if host != nil && host != "" {
			var hostSlice []string
			if str, ok := host.(string); ok {
				parts := strings.Split(str, ",")
				for _, part := range parts {
					hostSlice = append(hostSlice, strings.TrimSpace(part))
				}
			} else if slice, ok := host.([]interface{}); ok {
				for _, v := range slice {
					hostSlice = append(hostSlice, fmt.Sprintf("%v", v))
				}
			}
			if len(hostSlice) > 0 {
				transport["host"] = hostSlice
			}
		}
	}

	if h2Host := proxy["h2-host"]; h2Host != nil && h2Host != "" {
		var hostSlice []string
		if str, ok := h2Host.(string); ok {
			parts := strings.Split(str, ",")
			for _, part := range parts {
				hostSlice = append(hostSlice, strings.TrimSpace(part))
			}
		} else if slice, ok := h2Host.([]interface{}); ok {
			for _, v := range slice {
				hostSlice = append(hostSlice, fmt.Sprintf("%v", v))
			}
		}
		if len(hostSlice) > 0 {
			transport["host"] = hostSlice
		}
	}

	if h2Path := GetString(proxy, "h2-path"); h2Path != "" {
		transport["path"] = h2Path
	}

	// Simplify single-element arrays
	if host, ok := transport["host"].([]string); ok && len(host) == 1 {
		transport["host"] = host[0]
	}

	// Enable TLS for h2
	if tls, ok := parsed["tls"].(map[string]interface{}); ok {
		tls["enabled"] = true
	}

	parsed["transport"] = transport
}

func (p *SingboxProducer) grpcParser(proxy Proxy, parsed map[string]interface{}) {
	transport := map[string]interface{}{
		"type": "grpc",
	}

	grpcOpts := GetMap(proxy, "grpc-opts")
	if grpcOpts != nil {
		if serviceName := GetString(grpcOpts, "grpc-service-name"); serviceName != "" {
			transport["service_name"] = serviceName
		}
	}

	parsed["transport"] = transport
}

func (p *SingboxProducer) tlsParser(proxy Proxy, parsed map[string]interface{}) {
	tls := map[string]interface{}{
		"enabled": false,
	}

	if GetBool(proxy, "tls") {
		tls["enabled"] = true
	}

	if servername := GetString(proxy, "servername"); servername != "" {
		tls["server_name"] = servername
	}
	if peer := GetString(proxy, "peer"); peer != "" {
		tls["server_name"] = peer
	}
	if sni := GetString(proxy, "sni"); sni != "" {
		tls["server_name"] = sni
	}

	if GetBool(proxy, "skip-cert-verify") || GetBool(proxy, "insecure") {
		tls["insecure"] = true
	}

	if GetBool(proxy, "disable-sni") {
		tls["disable_sni"] = true
	}

	alpn := proxy["alpn"]
	if alpnStr, ok := alpn.(string); ok {
		tls["alpn"] = []string{alpnStr}
	} else if alpnSlice := GetStringSlice(proxy, "alpn"); alpnSlice != nil {
		tls["alpn"] = alpnSlice
	}

	if ca := GetString(proxy, "ca"); ca != "" {
		tls["certificate_path"] = ca
	}
	if caStr := GetString(proxy, "ca_str"); caStr != "" {
		tls["certificate"] = []string{caStr}
	}
	if caStr := GetString(proxy, "ca-str"); caStr != "" {
		tls["certificate"] = []string{caStr}
	}

	realityOpts := GetMap(proxy, "reality-opts")
	if realityOpts != nil {
		reality := map[string]interface{}{
			"enabled": true,
		}
		if publicKey := GetString(realityOpts, "public-key"); publicKey != "" {
			reality["public_key"] = publicKey
		}
		if shortID := GetString(realityOpts, "short-id"); shortID != "" {
			reality["short_id"] = shortID
		}
		tls["reality"] = reality
		tls["utls"] = map[string]interface{}{
			"enabled": true,
		}
	}

	proxyType := p.helper.GetProxyType(proxy)
	if proxyType != "hysteria" && proxyType != "hysteria2" && proxyType != "tuic" {
		if clientFingerprint := GetString(proxy, "client-fingerprint"); clientFingerprint != "" {
			tls["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": clientFingerprint,
			}
		}
	}

	// ech-opts
	if echMap := GetMap(proxy, "_ech"); echMap != nil {
		tls["ech"] = echMap
	} else if echOpts := GetMap(proxy, "ech-opts"); echOpts != nil {
		ech := map[string]interface{}{}
		if _, exists := tls["ech"]; exists {
			ech = tls["ech"].(map[string]interface{})
		}
		ech["enabled"] = GetBool(echOpts, "enable")
		if queryServerName := GetString(echOpts, "query-server-name"); queryServerName != "" {
			ech["query_server_name"] = queryServerName
		}
		if configPath := GetString(echOpts, "config-path"); configPath != "" {
			ech["config_path"] = configPath
		}
		// inline ECH config（PEM 按换行拆成字符串数组，对齐 Sub-Store）
		if cfgArr := GetStringSlice(echOpts, "config"); len(cfgArr) > 0 {
			ech["config"] = cfgArr
		} else if cfg := GetString(echOpts, "config"); cfg != "" {
			var lines []string
			for _, ln := range strings.Split(cfg, "\n") {
				if t := strings.TrimSpace(ln); t != "" {
					lines = append(lines, t)
				}
			}
			if len(lines) > 0 {
				ech["config"] = lines
			}
		}
		tls["ech"] = ech
	}

	if GetBool(proxy, "_fragment") {
		tls["fragment"] = true
	}
	if fragmentDelay := GetString(proxy, "_fragment_fallback_delay"); fragmentDelay != "" {
		tls["fragment_fallback_delay"] = fragmentDelay
	}
	if GetBool(proxy, "_record_fragment") {
		tls["record_fragment"] = true
	}
	if certificate := GetString(proxy, "_certificate"); certificate != "" {
		tls["certificate"] = certificate
	}
	if certificate_path := GetString(proxy, "_certificate_path"); certificate_path != "" {
		tls["certificate_path"] = certificate_path
	}
	if certificate_public_key_sha256 := GetString(proxy, "_certificate_public_key_sha256"); certificate_public_key_sha256 != "" {
		tls["certificate_public_key_sha256"] = certificate_public_key_sha256
	}
	if client_certificate := GetString(proxy, "_client_certificate"); client_certificate != "" {
		tls["client_certificate"] = client_certificate
	}
	if client_certificate_path := GetString(proxy, "_client_certificate_path"); client_certificate_path != "" {
		tls["client_certificate_path"] = client_certificate_path
	}
	if client_key := GetString(proxy, "_client_key"); client_key != "" {
		tls["client_key"] = client_key
	}
	if client_key_path := GetString(proxy, "_client_key_path"); client_key_path != "" {
		tls["client_key_path"] = client_key_path
	}

	// Only add tls if enabled
	if tls["enabled"].(bool) {
		parsed["tls"] = tls
	}
}

// Parser implementations

func (p *SingboxProducer) sshParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "ssh",
		"server":      GetString(proxy, "server"),
		"server_port": port,
	}

	if username := GetString(proxy, "username"); username != "" {
		parsed["user"] = username
	}
	if password := GetString(proxy, "password"); password != "" {
		parsed["password"] = password
	}

	if privateKey := GetString(proxy, "privateKey"); privateKey != "" {
		parsed["private_key_path"] = privateKey
	}
	if privateKey := GetString(proxy, "private-key"); privateKey != "" {
		parsed["private_key_path"] = privateKey
	}
	if passphrase := GetString(proxy, "private-key-passphrase"); passphrase != "" {
		parsed["private_key_passphrase"] = passphrase
	}

	if serverFingerprint := GetString(proxy, "server-fingerprint"); serverFingerprint != "" {
		parsed["host_key"] = []string{serverFingerprint}
		parts := strings.Fields(serverFingerprint)
		if len(parts) > 0 {
			parsed["host_key_algorithms"] = []string{parts[0]}
		}
	}

	if hostKey := GetStringSlice(proxy, "host-key"); hostKey != nil {
		parsed["host_key"] = hostKey
	}
	if hostKeyAlgorithms := GetStringSlice(proxy, "host-key-algorithms"); hostKeyAlgorithms != nil {
		parsed["host_key_algorithms"] = hostKeyAlgorithms
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) httpParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "http",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"tls": map[string]interface{}{
			"enabled":     false,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if username := GetString(proxy, "username"); username != "" {
		parsed["username"] = username
	}
	if password := GetString(proxy, "password"); password != "" {
		parsed["password"] = password
	}

	if headers := GetMap(proxy, "headers"); headers != nil {
		processedHeaders := make(map[string]string)
		for k, v := range headers {
			processedHeaders[k] = fmt.Sprintf("%v", v)
		}
		if len(processedHeaders) > 0 {
			parsed["headers"] = processedHeaders
		}
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) socks5Parser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "socks",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"version":     "5",
	}

	if username := GetString(proxy, "username"); username != "" {
		parsed["username"] = username
	}
	if password := GetString(proxy, "password"); password != "" {
		parsed["password"] = password
	}

	if GetBool(proxy, "uot") {
		parsed["udp_over_tcp"] = true
	}
	if GetBool(proxy, "udp-over-tcp") {
		version := GetInt(proxy, "udp-over-tcp-version")
		if version == 0 || version == 1 {
			version = 1
		} else {
			version = 2
		}
		parsed["udp_over_tcp"] = map[string]interface{}{
			"enabled": true,
			"version": version,
		}
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) shadowTLSParser(proxy Proxy) (map[string]interface{}, map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, nil, fmt.Errorf("invalid port")
	}

	name := GetString(proxy, "name")

	ssPart := map[string]interface{}{
		"tag":      name,
		"type":     "shadowsocks",
		"method":   GetString(proxy, "cipher"),
		"password": GetString(proxy, "password"),
		"detour":   fmt.Sprintf("%s_shadowtls", name),
	}

	if GetBool(proxy, "uot") {
		ssPart["udp_over_tcp"] = true
	}

	if GetBool(proxy, "udp-over-tcp") {
		version := GetInt(proxy, "udp-over-tcp-version")
		if version == 0 || version == 1 {
			version = 1
		} else {
			version = 2
		}
		ssPart["udp_over_tcp"] = map[string]interface{}{
			"enabled": true,
			"version": version,
		}
	}

	pluginOpts := GetMap(proxy, "plugin-opts")
	if pluginOpts == nil {
		return nil, nil, fmt.Errorf("plugin-opts required for shadow-tls")
	}

	stPart := map[string]interface{}{
		"tag":         fmt.Sprintf("%s_shadowtls", name),
		"type":        "shadowtls",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"version":     GetInt(pluginOpts, "version"),
		"password":    GetString(pluginOpts, "password"),
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(pluginOpts, "host"),
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": GetString(proxy, "client-fingerprint"),
			},
		},
	}

	if GetBool(proxy, "fast-open") {
		stPart["udp_fragment"] = true
	}

	p.tfoParser(proxy, stPart)
	p.detourParser(proxy, stPart)
	p.smuxParser(proxy, ssPart)
	p.ipVersionParser(proxy, stPart)
	p.domainResolverParser(proxy, stPart)

	return ssPart, stPart, nil
}

func (p *SingboxProducer) ssParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "shadowsocks",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"method":      GetString(proxy, "cipher"),
		"password":    GetString(proxy, "password"),
	}

	if GetBool(proxy, "uot") {
		parsed["udp_over_tcp"] = true
	}

	if GetBool(proxy, "udp-over-tcp") {
		version := GetInt(proxy, "udp-over-tcp-version")
		if version == 0 || version == 1 {
			version = 1
		} else {
			version = 2
		}
		parsed["udp_over_tcp"] = map[string]interface{}{
			"enabled": true,
			"version": version,
		}
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)

	// Handle plugin
	if plugin := GetString(proxy, "plugin"); plugin != "" {
		pluginOpts := GetMap(proxy, "plugin-opts")
		if pluginOpts == nil {
			pluginOpts = make(map[string]interface{})
		}

		var optArr []string

		switch plugin {
		case "obfs":
			parsed["plugin"] = "obfs-local"
			if obfsHost := GetString(proxy, "obfs-host"); obfsHost != "" {
				pluginOpts["host"] = obfsHost
			}

			for k, v := range pluginOpts {
				switch k {
				case "mode":
					optArr = append(optArr, fmt.Sprintf("obfs=%v", v))
				case "host":
					optArr = append(optArr, fmt.Sprintf("obfs-host=%v", v))
				default:
					optArr = append(optArr, fmt.Sprintf("%s=%v", k, v))
				}
			}
		case "v2ray-plugin":
			parsed["plugin"] = "v2ray-plugin"
			if wsHost := GetString(proxy, "ws-host"); wsHost != "" {
				pluginOpts["host"] = wsHost
			}
			if wsPath := GetString(proxy, "ws-path"); wsPath != "" {
				pluginOpts["path"] = wsPath
			}

			for k, v := range pluginOpts {
				switch k {
				case "tls":
					if GetBool(pluginOpts, "tls") {
						optArr = append(optArr, "tls")
					}
				case "host":
					optArr = append(optArr, fmt.Sprintf("host=%v", v))
				case "path":
					optArr = append(optArr, fmt.Sprintf("path=%v", v))
				case "headers":
					jsonBytes, _ := json.Marshal(v)
					optArr = append(optArr, fmt.Sprintf("headers=%s", string(jsonBytes)))
				case "mux":
					if GetBool(pluginOpts, "mux") {
						parsed["multiplex"] = map[string]interface{}{
							"enabled": true,
						}
					}
				default:
					optArr = append(optArr, fmt.Sprintf("%s=%v", k, v))
				}
			}
		}

		if len(optArr) > 0 {
			parsed["plugin_opts"] = strings.Join(optArr, ";")
		}
	}

	return parsed, nil
}

func (p *SingboxProducer) ssrParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "shadowsocksr",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"method":      GetString(proxy, "cipher"),
		"password":    GetString(proxy, "password"),
		"obfs":        GetString(proxy, "obfs"),
		"protocol":    GetString(proxy, "protocol"),
	}

	if obfsParam := GetString(proxy, "obfs-param"); obfsParam != "" {
		parsed["obfs_param"] = obfsParam
	}

	if protocolParam := GetString(proxy, "protocol-param"); protocolParam != "" {
		parsed["protocol_param"] = protocolParam
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) vmessParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	security := GetString(proxy, "cipher")
	validSecurity := []string{"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr"}
	isValid := false
	for _, s := range validSecurity {
		if s == security {
			isValid = true
			break
		}
	}
	if !isValid {
		security = "auto"
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "vmess",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"uuid":        GetString(proxy, "uuid"),
		"security":    security,
		"alter_id":    GetInt(proxy, "alterId"),
		"tls": map[string]interface{}{
			"enabled":     false,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if pe := GetString(proxy, "packet-encoding"); pe != "" {
		parsed["packet_encoding"] = pe
	} else if GetBool(proxy, "packet-addr") {
		parsed["packet_encoding"] = "packetaddr"
	} else if GetBool(proxy, "xudp") {
		parsed["packet_encoding"] = "xudp"
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	network := GetString(proxy, "network")
	switch network {
	case "ws":
		p.wsParser(proxy, parsed)
	case "h2":
		p.h2Parser(proxy, parsed)
	case "http":
		p.h1Parser(proxy, parsed)
	case "grpc":
		p.grpcParser(proxy, parsed)
	}

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) vlessParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "vless",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"uuid":        GetString(proxy, "uuid"),
		"tls": map[string]interface{}{
			"enabled":     false,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if pe := GetString(proxy, "packet-encoding"); pe != "" {
		parsed["packet_encoding"] = pe
	} else if GetBool(proxy, "packet-addr") {
		parsed["packet_encoding"] = "packetaddr"
	} else if GetBool(proxy, "xudp") {
		parsed["packet_encoding"] = "xudp"
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	if flow := GetString(proxy, "flow"); flow != "" {
		parsed["flow"] = flow
	}

	network := GetString(proxy, "network")
	switch network {
	case "ws":
		p.wsParser(proxy, parsed)
	case "h2":
		p.h2Parser(proxy, parsed)
	case "http":
		p.h1Parser(proxy, parsed)
	case "grpc":
		p.grpcParser(proxy, parsed)
	}

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) trojanParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "trojan",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"password":    GetString(proxy, "password"),
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	network := GetString(proxy, "network")
	switch network {
	case "grpc":
		p.grpcParser(proxy, parsed)
	case "ws":
		p.wsParser(proxy, parsed)
	}

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) hysteriaParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":                   GetString(proxy, "name"),
		"type":                  "hysteria",
		"server":                GetString(proxy, "server"),
		"server_port":           port,
		"disable_mtu_discovery": false,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if hopInterval := GetString(proxy, "hop-interval"); hopInterval != "" {
		if matched, _ := regexp.MatchString(`^\d+$`, hopInterval); matched {
			parsed["hop_interval"] = fmt.Sprintf("%ss", hopInterval)
		} else {
			parsed["hop_interval"] = hopInterval
		}
	}

	if ports := GetString(proxy, "ports"); ports != "" {
		portList := regexp.MustCompile(`\s*,\s*`).Split(ports, -1)
		serverPorts := make([]string, 0, len(portList))
		for _, p := range portList {
			rangeStr := regexp.MustCompile(`\s*-\s*`).ReplaceAllString(p, ":")
			if strings.Contains(rangeStr, ":") {
				serverPorts = append(serverPorts, rangeStr)
			} else {
				serverPorts = append(serverPorts, fmt.Sprintf("%s:%s", rangeStr, rangeStr))
			}
		}
		parsed["server_ports"] = serverPorts
	}

	if authStr := GetString(proxy, "auth_str"); authStr != "" {
		parsed["auth_str"] = authStr
	}
	if authStr := GetString(proxy, "auth-str"); authStr != "" {
		parsed["auth_str"] = authStr
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	// Handle bandwidth
	reg := regexp.MustCompile(`^[0-9]+[ \t]*[KMGT]*[Bb]ps$`)
	upStr := GetString(proxy, "up")
	if upStr == "" {
		upStr = fmt.Sprintf("%d", GetInt(proxy, "up"))
	}
	if reg.MatchString(upStr) && !strings.HasSuffix(upStr, "Mbps") {
		parsed["up"] = upStr
	} else {
		up := GetInt(proxy, "up")
		if up > 0 {
			parsed["up_mbps"] = up
		}
	}

	downStr := GetString(proxy, "down")
	if downStr == "" {
		downStr = fmt.Sprintf("%d", GetInt(proxy, "down"))
	}
	if reg.MatchString(downStr) && !strings.HasSuffix(downStr, "Mbps") {
		parsed["down"] = downStr
	} else {
		down := GetInt(proxy, "down")
		if down > 0 {
			parsed["down_mbps"] = down
		}
	}

	if obfs := GetString(proxy, "obfs"); obfs != "" {
		parsed["obfs"] = obfs
	}

	if recvWindowConn := GetInt(proxy, "recv_window_conn"); recvWindowConn > 0 {
		parsed["recv_window_conn"] = recvWindowConn
	}
	if recvWindowConn := GetInt(proxy, "recv-window-conn"); recvWindowConn > 0 {
		parsed["recv_window_conn"] = recvWindowConn
	}

	if recvWindow := GetInt(proxy, "recv_window"); recvWindow > 0 {
		parsed["recv_window"] = recvWindow
	}
	if recvWindow := GetInt(proxy, "recv-window"); recvWindow > 0 {
		parsed["recv_window"] = recvWindow
	}

	if disableMTU, ok := proxy["disable_mtu_discovery"].(bool); ok {
		parsed["disable_mtu_discovery"] = disableMTU
	} else if disableMTU := GetInt(proxy, "disable_mtu_discovery"); disableMTU == 1 {
		parsed["disable_mtu_discovery"] = true
	}

	p.networkParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) hysteria2Parser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "hysteria2",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"password":    GetString(proxy, "password"),
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if hopInterval := GetString(proxy, "hop-interval"); hopInterval != "" {
		if matched, _ := regexp.MatchString(`^\d+$`, hopInterval); matched {
			parsed["hop_interval"] = fmt.Sprintf("%ss", hopInterval)
		} else {
			parsed["hop_interval"] = hopInterval
		}
	}

	if ports := GetString(proxy, "ports"); ports != "" {
		portList := regexp.MustCompile(`\s*,\s*`).Split(ports, -1)
		serverPorts := make([]string, 0, len(portList))
		for _, p := range portList {
			rangeStr := regexp.MustCompile(`\s*-\s*`).ReplaceAllString(p, ":")
			if strings.Contains(rangeStr, ":") {
				serverPorts = append(serverPorts, rangeStr)
			} else {
				serverPorts = append(serverPorts, fmt.Sprintf("%s:%s", rangeStr, rangeStr))
			}
		}
		parsed["server_ports"] = serverPorts
	}

	if up := GetInt(proxy, "up"); up > 0 {
		parsed["up_mbps"] = up
	}

	if down := GetInt(proxy, "down"); down > 0 {
		parsed["down_mbps"] = down
	}

	obfsType := GetString(proxy, "obfs")
	obfsPassword := GetString(proxy, "obfs-password")
	if obfsType == "salamander" || obfsPassword != "" {
		obfs := make(map[string]interface{})
		if obfsType == "salamander" {
			obfs["type"] = "salamander"
		}
		if obfsPassword != "" {
			obfs["password"] = obfsPassword
		}
		if len(obfs) > 0 {
			parsed["obfs"] = obfs
		}
	}

	p.networkParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) tuic5Parser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "tuic",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"uuid":        GetString(proxy, "uuid"),
		"password":    GetString(proxy, "password"),
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	if congestionController := GetString(proxy, "congestion-controller"); congestionController != "" && congestionController != "cubic" {
		parsed["congestion_control"] = congestionController
	}

	if udpRelayMode := GetString(proxy, "udp-relay-mode"); udpRelayMode != "" && udpRelayMode != "native" {
		parsed["udp_relay_mode"] = udpRelayMode
	}

	if GetBool(proxy, "reduce-rtt") {
		parsed["zero_rtt_handshake"] = true
	}

	if GetBool(proxy, "udp-over-stream") {
		parsed["udp_over_stream"] = true
	}

	if heartbeatInterval := GetString(proxy, "heartbeat-interval"); heartbeatInterval != "" {
		parsed["heartbeat"] = fmt.Sprintf("%sms", heartbeatInterval)
	}

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) anytlsParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "anytls",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"password":    GetString(proxy, "password"),
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if idleSessionCheckInterval := GetString(proxy, "idle-session-check-interval"); idleSessionCheckInterval != "" {
		if matched, _ := regexp.MatchString(`^\d+$`, idleSessionCheckInterval); matched {
			parsed["idle_session_check_interval"] = fmt.Sprintf("%ss", idleSessionCheckInterval)
		}
	}

	if idleSessionTimeout := GetString(proxy, "idle-session-timeout"); idleSessionTimeout != "" {
		if matched, _ := regexp.MatchString(`^\d+$`, idleSessionTimeout); matched {
			parsed["idle_session_timeout"] = fmt.Sprintf("%ss", idleSessionTimeout)
		}
	}

	if minIdleSession := GetString(proxy, "min-idle-session"); minIdleSession != "" {
		if matched, _ := regexp.MatchString(`^\d+$`, minIdleSession); matched {
			parsed["min_idle_session"], _ = strconv.Atoi(minIdleSession)
		}
	}

	p.networkParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)

	return parsed, nil
}

func (p *SingboxProducer) naiveParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "naive",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": GetString(proxy, "server"),
			"insecure":    false,
		},
	}

	if username := GetString(proxy, "username"); username != "" {
		parsed["username"] = username
	}
	if password := GetString(proxy, "password"); password != "" {
		parsed["password"] = password
	}

	if GetBool(proxy, "uot") {
		parsed["udp_over_tcp"] = true
	}
	if GetBool(proxy, "udp-over-tcp") {
		version := GetInt(proxy, "udp-over-tcp-version")
		if version == 0 || version == 1 {
			version = 1
		} else {
			version = 2
		}
		parsed["udp_over_tcp"] = map[string]interface{}{
			"enabled": true,
			"version": version,
		}
	}

	if insecureConcurrency := GetInt(proxy, "insecure-concurrency"); insecureConcurrency > 0 {
		parsed["insecure_concurrency"] = insecureConcurrency
	}

	if extraHeaders := GetMap(proxy, "extra-headers"); extraHeaders != nil {
		parsed["extra_headers"] = extraHeaders
	}

	if GetBool(proxy, "quic") {
		parsed["quic"] = true
	}
	if qcc := GetString(proxy, "quic-congestion-control"); qcc != "" {
		parsed["quic_congestion_control"] = qcc
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.tlsParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)

	// naive doesn't support tls.insecure
	if tls, ok := parsed["tls"].(map[string]interface{}); ok {
		delete(tls, "insecure")
	}

	return parsed, nil
}

func (p *SingboxProducer) wireguardParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}

	address := make([]string, 0)
	if ip := GetString(proxy, "ip"); ip != "" {
		if strings.Contains(ip, "/") {
			address = append(address, ip)
		} else if IsIPv4(ip) {
			address = append(address, fmt.Sprintf("%s/32", ip))
		}
	}
	if ipv6 := GetString(proxy, "ipv6"); ipv6 != "" {
		if strings.Contains(ipv6, "/") {
			address = append(address, ipv6)
		} else if IsIPv6(ipv6) {
			address = append(address, fmt.Sprintf("%s/128", ipv6))
		}
	}

	parsed := map[string]interface{}{
		"tag":             GetString(proxy, "name"),
		"type":            "wireguard",
		"server":          GetString(proxy, "server"),
		"server_port":     port,
		"address":         address,
		"private_key":     GetString(proxy, "private-key"),
		"peer_public_key": GetString(proxy, "public-key"),
		"pre_shared_key":  GetString(proxy, "pre-shared-key"),
	}

	if GetBool(proxy, "system") {
		parsed["system"] = true
	}
	if mtu := GetInt(proxy, "mtu"); mtu > 0 {
		parsed["mtu"] = mtu
	}
	if udpTimeout := GetString(proxy, "udp-timeout"); udpTimeout != "" {
		parsed["udp_timeout"] = udpTimeout
	}
	if workers := GetInt(proxy, "workers"); workers > 0 {
		parsed["workers"] = workers
	}

	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}

	// Handle reserved
	parsedReserved := parseReserved(proxy["reserved"])
	if parsedReserved != nil {
		parsed["reserved"] = parsedReserved
	}

	// Ensure peers exist
	peersSlice, _ := proxy["peers"].([]interface{})
	if len(peersSlice) == 0 {
		peersSlice = []interface{}{map[string]interface{}{}}
	}

	peers := make([]map[string]interface{}, 0, len(peersSlice))
	for _, peerInterface := range peersSlice {
		peerMap, ok := peerInterface.(map[string]interface{})
		if !ok {
			continue
		}

		peerServer := GetString(peerMap, "server")
		peerPort := GetInt(peerMap, "port")
		if peerServer == "" {
			peerServer = GetString(proxy, "server")
		}
		if peerPort == 0 {
			peerPort = port
		}

		publicKey := GetString(peerMap, "public-key")
		if publicKey == "" {
			publicKey = GetString(peerMap, "public_key")
		}
		if publicKey == "" {
			publicKey = GetString(proxy, "public-key")
		}

		preSharedKey := GetString(peerMap, "pre-shared-key")
		if preSharedKey == "" {
			preSharedKey = GetString(peerMap, "pre_shared_key")
		}
		if preSharedKey == "" {
			preSharedKey = GetString(proxy, "pre-shared-key")
		}

		allowedIPs := GetStringSlice(peerMap, "allowed-ips")
		if allowedIPs == nil {
			allowedIPs = GetStringSlice(peerMap, "allowed_ips")
		}
		if allowedIPs == nil {
			allowedIPs = []string{"0.0.0.0/0"}
			if GetString(proxy, "ipv6") != "" {
				allowedIPs = append(allowedIPs, "::/0")
			}
		}

		peer := map[string]interface{}{
			"address":    peerServer,
			"port":       peerPort,
			"public_key": publicKey,
			"allowed_ips": allowedIPs,
		}
		if preSharedKey != "" {
			peer["pre_shared_key"] = preSharedKey
		}

		if keepalive := GetInt(peerMap, "persistent-keepalive-interval"); keepalive > 0 {
			peer["persistent_keepalive_interval"] = keepalive
		}

		peerReserved := parseReserved(peerMap["reserved"])
		if peerReserved == nil {
			peerReserved = parsedReserved
		}
		if peerReserved != nil {
			peer["reserved"] = peerReserved
		}

		peers = append(peers, peer)
	}
	parsed["peers"] = peers

	p.networkParser(proxy, parsed)
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.smuxParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)

	delete(parsed, "server")
	delete(parsed, "server_port")
	delete(parsed, "pre_shared_key")
	delete(parsed, "peer_public_key")
	delete(parsed, "reserved")

	return parsed, nil
}

func parseReserved(reserved interface{}) interface{} {
	if reserved == nil {
		return nil
	}
	if str, ok := reserved.(string); ok {
		return str
	}
	if slice, ok := reserved.([]interface{}); ok && len(slice) > 0 {
		nums := make([]int, 0, len(slice))
		for _, v := range slice {
			switch n := v.(type) {
			case int:
				nums = append(nums, n)
			case float64:
				nums = append(nums, int(n))
			}
		}
		if len(nums) > 0 {
			return nums
		}
	}
	return nil
}

// snellParser 移植自 Sub-Store sing-box.js:sing-box 支持 snell v4/5/6,v5 输出转 v4;
// v6 用 mode(default/unshaped/unsafe-raw),v4/5 用 obfs_mode/obfs_host。缺省版本不校验。
// (shadow-tls detour 属小众,mmwX 范围内不处理。)
func (p *SingboxProducer) snellParser(proxy Proxy) (map[string]interface{}, error) {
	port := GetInt(proxy, "port")
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}
	version := GetInt(proxy, "version")
	if version != 0 && version != 4 && version != 5 && version != 6 {
		return nil, fmt.Errorf("platform sing-box does not support snell version %v", proxy["version"])
	}
	outputVersion := version
	if version == 5 {
		outputVersion = 4
	}

	parsed := map[string]interface{}{
		"tag":         GetString(proxy, "name"),
		"type":        "snell",
		"server":      GetString(proxy, "server"),
		"server_port": port,
		"psk":         GetString(proxy, "psk"),
	}
	if outputVersion != 0 {
		parsed["version"] = outputVersion
	}
	if uk := GetString(proxy, "_userkey"); uk != "" {
		parsed["userkey"] = uk
	}
	if outputVersion == 6 {
		if mode := GetString(proxy, "mode"); mode != "" {
			parsed["mode"] = mode
		}
	} else if obfsOpts := GetMap(proxy, "obfs-opts"); obfsOpts != nil {
		if mode := GetString(obfsOpts, "mode"); mode != "" && mode != "shadow-tls" {
			parsed["obfs_mode"] = mode
			if host := GetString(obfsOpts, "host"); host != "" {
				parsed["obfs_host"] = host
			}
		}
	}
	if GetBool(proxy, "reuse") && (version == 0 || version >= 4) {
		parsed["reuse"] = true
	}
	p.networkParser(proxy, parsed)
	if GetBool(proxy, "fast-open") {
		parsed["udp_fragment"] = true
	}
	p.tfoParser(proxy, parsed)
	p.detourParser(proxy, parsed)
	p.ipVersionParser(proxy, parsed)
	p.domainResolverParser(proxy, parsed)
	return parsed, nil
}
