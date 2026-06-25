package substore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// SurgeMacProducer implements Surge for macOS format converter
type SurgeMacProducer struct {
	producerType  string
	surgeProducer *SurgeProducer
	helper        *ProxyHelper
}

// NewSurgeMacProducer creates a new Surge for macOS producer
func NewSurgeMacProducer() *SurgeMacProducer {
	return &SurgeMacProducer{
		producerType:  "surgemac",
		surgeProducer: NewSurgeProducer(),
		helper:        NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *SurgeMacProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Surge for macOS format
func (p *SurgeMacProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	var result []string
	for _, proxy := range proxies {
		// 对齐 JS: ProduceOne 内部已处理 external / mihomo 直连与 mihomo 回退，
		// 这里出错即跳过该节点（JS 中 produce 抛错时由上层过滤）。
		line, err := p.ProduceOne(proxy, outputType, opts)
		if err != nil || line == "" {
			// 对齐 JS: 出错或返回空字符串（如 mihomo 直连失败、snell v6 obfs 不支持）的节点被过滤。
			continue
		}
		result = append(result, line)
	}

	if outputType == "internal" {
		return proxies, nil
	}

	output := ""
	for _, line := range result {
		output += line + "\n"
	}
	return output, nil
}

// ProduceOne converts a single proxy to Surge for macOS format
func (p *SurgeMacProducer) ProduceOne(proxy Proxy, outputType string, opts *ProduceOptions) (string, error) {
	proxyType := p.helper.GetProxyType(proxy)

	switch proxyType {
	case "external":
		return p.produceExternal(proxy)
	default:
		// 对齐 JS: if (opts.mihomoExternal || proxy._mihomoExternal) 直接走 mihomo。
		// ProduceOptions 无 mihomoExternal 字段（types.go 为共享类型，不在本任务范围内改动），
		// 因此仅镜像 proxy._mihomoExternal 这一路径。
		if surgemacIsMihomoExternal(proxy) {
			if line, err := p.produceMihomo(proxy, outputType, opts); err == nil {
				return line, nil
			}
			return "", nil
		}
		// Try to use the standard Surge producer
		result, err := p.surgeProducer.ProduceOne(proxy, outputType, opts)
		if err != nil {
			// If useMihomoExternal is enabled, try mihomo fallback
			if opts != nil && opts.UseMihomoExternal {
				return p.produceMihomo(proxy, outputType, opts)
			}
			return "", fmt.Errorf("surge for macOS does not support %s. Use target=SurgeMac with useMihomoExternal to enable mihomo support", proxyType)
		}
		return result, nil
	}
}

// produceExternal produces an external proxy configuration
func (p *SurgeMacProducer) produceExternal(proxy Proxy) (string, error) {
	result := &Result{Proxy: proxy}

	exec := GetString(proxy, "exec")

	// 对齐 JS: if (!proxy.exec || !proxy['local-port']) 抛错。
	// 纠正性偏离：原 Go 用 GetInt 兜底会把缺失/0 的 local-port 变成 "0" 从而绕过校验，
	// 这里改用 IsPresent 严格判断 exec 与 local-port 是否存在，避免生成无效 external 行。
	if exec == "" || !IsPresent(proxy, "exec") || !IsPresent(proxy, "local-port") {
		return "", fmt.Errorf("external: exec and local-port are required")
	}

	localPort := GetString(proxy, "local-port")
	if localPort == "" {
		localPort = fmt.Sprintf("%d", GetInt(proxy, "local-port"))
	}

	result.Append(fmt.Sprintf(`%s=external,exec="%s",local-port=%s`,
		p.helper.GetProxyName(proxy), exec, localPort))

	// Args
	if IsPresent(proxy, "args") {
		args := GetStringSlice(proxy, "args")
		for _, arg := range args {
			result.Append(fmt.Sprintf(`,args="%s"`, arg))
		}
	}

	// Addresses
	if IsPresent(proxy, "addresses") {
		addresses := GetStringSlice(proxy, "addresses")
		for _, addr := range addresses {
			result.Append(fmt.Sprintf(`,addresses=%s`, addr))
		}
	}

	// no-error-alert
	result.AppendIfPresent(`,no-error-alert=%v`, "no-error-alert")

	// udp
	// 对齐 JS surgemac external: result.appendIfPresent(`,udp-relay=${proxy.udp}`, 'udp')
	result.AppendIfPresent(`,udp-relay=%v`, "udp")

	// tfo
	if IsPresent(proxy, "tfo") {
		result.Append(fmt.Sprintf(`,tfo=%v`, GetBool(proxy, "tfo")))
	} else if IsPresent(proxy, "fast-open") {
		result.Append(fmt.Sprintf(`,tfo=%v`, GetBool(proxy, "fast-open")))
	}

	// test-url
	result.AppendIfPresent(`,test-url=%s`, "test-url")

	// block-quic
	result.AppendIfPresent(`,block-quic=%v`, "block-quic")

	return result.String(), nil
}

// produceMihomo produces a mihomo external proxy configuration
func (p *SurgeMacProducer) produceMihomo(proxy Proxy, _ string, opts *ProduceOptions) (string, error) {
	// Convert to ClashMeta format first
	clashMetaProducer := NewClashMetaProducer()
	clashProxies, err := clashMetaProducer.Produce([]Proxy{proxy}, "internal", nil)
	if err != nil {
		return "", err
	}

	clashProxyList, ok := clashProxies.([]Proxy)
	if !ok || len(clashProxyList) == 0 {
		return "", fmt.Errorf("failed to convert proxy to ClashMeta format")
	}

	clashProxy := clashProxyList[0]

	// Get local port
	localPort := 0
	if opts != nil {
		localPort = opts.LocalPort
	}
	if localPort == 0 {
		localPort = GetInt(proxy, "_localPort")
	}
	if localPort == 0 {
		localPort = 65535
	}

	// Determine IPv6 support
	ipVersion := GetString(proxy, "ip-version")
	ipv6 := true
	if ipVersion == "ipv4" || ipVersion == "v4-only" {
		ipv6 = false
	}

	// Get nameservers
	var defaultNameserver []string
	if opts != nil && len(opts.DefaultNameserver) > 0 {
		defaultNameserver = opts.DefaultNameserver
	} else {
		defaultNameserver = GetStringSlice(proxy, "_defaultNameserver")
	}
	if len(defaultNameserver) == 0 {
		defaultNameserver = []string{
			"180.76.76.76",
			"52.80.52.52",
			"119.28.28.28",
			"223.6.6.6",
		}
	}

	var nameserver []string
	if opts != nil && len(opts.Nameserver) > 0 {
		nameserver = opts.Nameserver
	} else {
		nameserver = GetStringSlice(proxy, "_nameserver")
	}
	if len(nameserver) == 0 {
		nameserver = []string{
			"https://doh.pub/dns-query",
			"https://dns.alidns.com/dns-query",
			"https://doh-pure.onedns.net/dns-query",
		}
	}

	// Build mihomo config
	clashProxy["name"] = "proxy"
	mihomoConfig := map[string]interface{}{
		"mixed-port": localPort,
		"ipv6":       ipv6,
		"mode":       "global",
		"dns": map[string]interface{}{
			"enable":             true,
			"ipv6":               ipv6,
			"default-nameserver": defaultNameserver,
			"nameserver":         nameserver,
		},
		"proxies": []interface{}{clashProxy},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name":    "GLOBAL",
				"type":    "select",
				"proxies": []string{"proxy"},
			},
		},
	}

	// Encode config to base64
	configJSON, err := json.Marshal(mihomoConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal mihomo config: %v", err)
	}
	configBase64 := base64.StdEncoding.EncodeToString(configJSON)

	// Get exec path
	exec := GetString(proxy, "_exec")
	if exec == "" {
		exec = "/usr/local/bin/mihomo"
	}

	// Build external proxy
	// 对齐 JS surgemac mihomo(): external_proxy 携带 udp: true，
	// 由 external() 输出为 ,udp-relay=true
	externalProxy := Proxy{
		"name":       p.helper.GetProxyName(proxy),
		"type":       "external",
		"udp":        true,
		"exec":       exec,
		"local-port": localPort,
		"args":       []string{"-config", configBase64},
		"addresses":  []string{},
	}

	// Validate server address is an IP
	server := p.helper.GetProxyServer(proxy)
	if IsIPv4(server) || IsIPv6(server) {
		externalProxy["addresses"] = []string{server}
	} else {
		// Note: In production, this should log a warning
		// For now, we'll just skip adding the address
	}

	// Update opts for next proxy
	if opts != nil {
		opts.LocalPort = localPort - 1
	}

	return p.produceExternal(externalProxy)
}

// surgemacIsMihomoExternal 判断 proxy 是否标记了 _mihomoExternal（对齐 JS proxy._mihomoExternal）。
func surgemacIsMihomoExternal(proxy Proxy) bool {
	if !IsPresent(proxy, "_mihomoExternal") {
		return false
	}
	return GetBool(proxy, "_mihomoExternal")
}
