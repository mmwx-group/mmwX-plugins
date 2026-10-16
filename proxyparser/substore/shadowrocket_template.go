package substore

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

// ShadowrocketTemplateProducer implements Shadowrocket format converter
type ShadowrocketTemplateProducer struct {
	producerType string
	helper       *ProxyHelper
}

// NewShadowrocketTemplateProducer creates a new Shadowrocket template producer
func NewShadowrocketTemplateProducer() *ShadowrocketTemplateProducer {
	return &ShadowrocketTemplateProducer{
		producerType: "shadowrocket",
		helper:       NewProxyHelper(),
	}
}

// GetType returns the producer type
func (p *ShadowrocketTemplateProducer) GetType() string {
	return p.producerType
}

// Produce converts proxies to Shadowrocket format
func (p *ShadowrocketTemplateProducer) Produce(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	if opts == nil {
		opts = &ProduceOptions{}
	}

	// 如果只需要内部格式或没有完整配置，使用原有的简化逻辑
	if outputType == "internal" || opts.FullConfig == nil {
		return p.produceProxiesOnly(proxies, outputType, opts)
	}

	// 生成完整的 Shadowrocket 配置
	return p.produceFullConfig(proxies, opts)
}

// produceProxiesOnly 只生成节点部分（向后兼容）
func (p *ShadowrocketTemplateProducer) produceProxiesOnly(proxies []Proxy, outputType string, opts *ProduceOptions) (interface{}, error) {
	result := p.transformProxies(proxies, opts)

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

// produceFullConfig 生成完整的 Shadowrocket 配置文件
func (p *ShadowrocketTemplateProducer) produceFullConfig(proxies []Proxy, opts *ProduceOptions) (string, error) {
	var sb strings.Builder

	// [General]
	sb.WriteString(p.generateGeneral(opts))
	sb.WriteString("\n")

	// [Proxy]
	proxySection, outputNames, outputOrder := p.generateProxies(proxies, opts)
	sb.WriteString(proxySection)
	sb.WriteString("\n")

	// 写不出来的节点(Mieru、多 peer 的 WireGuard 等)没有输出,
	// 组和规则里指向它们的名字要一并清理(见 policy_prune.go)。
	inputNames := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		inputNames = append(inputNames, GetString(proxy, "name"))
	}
	groups := srExpandProxyGroups(shadowrocketProxyGroups(opts.FullConfig), outputOrder)
	groupRefs := make([]policyGroupMembers, len(groups))
	for i, g := range groups {
		groupRefs[i] = policyGroupMembers{Name: g.name, Members: g.members, Empty: g.empty}
	}
	pruned := prunePolicyGroups(groupRefs, inputNames, outputNames)

	// [Proxy Group]
	sb.WriteString(p.generateProxyGroups(groups, pruned))
	sb.WriteString("\n")

	// [Rule]
	sb.WriteString(p.generateRules(opts, pruned.Dangling))
	sb.WriteString("\n")

	// [Host]
	sb.WriteString(p.generateHost())
	sb.WriteString("\n")

	// [URL Rewrite]
	sb.WriteString("[URL Rewrite]\n")
	sb.WriteString("# Google搜索引擎防跳转\n")
	sb.WriteString("^https?://(www.)?g.cn https://www.google.com 302\n")
	sb.WriteString("^https?://(www.)?google.cn https://www.google.com 302\n")
	sb.WriteString("\n")

	// [MITM]
	sb.WriteString("[MITM]\n")
	sb.WriteString("hostname = www.google.cn\n")

	return sb.String(), nil
}

// generateGeneral 生成 [General] 部分
func (p *ShadowrocketTemplateProducer) generateGeneral(opts *ProduceOptions) string {
	var sb strings.Builder
	sb.WriteString("[General]\n")
	sb.WriteString("bypass-system = true\n")
	sb.WriteString("skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com\n")
	sb.WriteString("tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32\n")

	// DNS 配置
	dnsServers := p.extractDNSServers(opts.FullConfig)
	if len(dnsServers) > 0 {
		sb.WriteString("dns-server = ")
		sb.WriteString(strings.Join(dnsServers, ","))
		sb.WriteString("\n")
	} else {
		sb.WriteString("dns-server = https://120.53.53.53/dns-query,https://dns.alidns.com/dns-query,223.5.5.5,119.29.29.29\n")
	}

	// IPv6 配置
	ipv6 := p.extractIPv6Config(opts.FullConfig)
	sb.WriteString(fmt.Sprintf("ipv6 = %v\n", ipv6))

	sb.WriteString("fallback-dns-server = system\n")
	sb.WriteString("prefer-ipv6 = false\n")
	sb.WriteString("dns-direct-system = false\n")
	sb.WriteString("icmp-auto-reply = true\n")
	sb.WriteString("always-reject-url-rewrite = false\n")
	sb.WriteString("private-ip-answer = true\n")
	sb.WriteString("dns-direct-fallback-proxy = false\n")
	sb.WriteString("udp-policy-not-supported-behaviour = REJECT\n")

	return sb.String()
}

// extractDNSServers 从 Clash 配置中提取 DNS 服务器
func (p *ShadowrocketTemplateProducer) extractDNSServers(fullConfig map[string]interface{}) []string {
	var servers []string

	if dnsConfig, ok := fullConfig["dns"].(map[string]interface{}); ok {
		// 提取 nameserver
		if nameserver, ok := dnsConfig["nameserver"].([]interface{}); ok {
			for _, ns := range nameserver {
				if nsStr, ok := ns.(string); ok {
					servers = append(servers, nsStr)
				}
			}
		}
	}

	return servers
}

// extractIPv6Config 从 Clash 配置中提取 IPv6 配置
func (p *ShadowrocketTemplateProducer) extractIPv6Config(fullConfig map[string]interface{}) bool {
	if dnsConfig, ok := fullConfig["dns"].(map[string]interface{}); ok {
		if ipv6, ok := dnsConfig["ipv6"].(bool); ok {
			return ipv6
		}
	}
	return false
}

// generateProxies 生成 [Proxy] 部分,同时返回实际输出了的节点名(写成注释的不算)及其顺序。
// 写不出来的节点一律留一行注释说明原因 —— 以前有几类是静默丢掉的,节点全丢光时
// 用户只看到空的 [Proxy] 和全变成 DIRECT 的规则,无从查起。
func (p *ShadowrocketTemplateProducer) generateProxies(proxies []Proxy, opts *ProduceOptions) (string, map[string]bool, []string) {
	var sb strings.Builder
	sb.WriteString("[Proxy]\n")
	sb.WriteString("# 节点配置\n")

	outputNames := make(map[string]bool)
	var outputOrder []string
	transformed := p.transformProxies(proxies, opts)
	kept := make(map[string]bool, len(transformed))
	for _, proxy := range transformed {
		kept[GetString(proxy, "name")] = true
	}
	for _, proxy := range proxies {
		if name := GetString(proxy, "name"); !kept[name] {
			sb.WriteString(fmt.Sprintf("# 已跳过 %s: %s(Shadowrocket 不支持)\n", GetString(proxy, "type"), name))
		}
	}

	for _, proxy := range transformed {
		proxyType := GetString(proxy, "type")
		name := GetString(proxy, "name")

		// 在兼容模式下,过滤不兼容的节点
		if opts != nil && opts.ClientCompatibilityMode {
			if proxyType == "wireguard" {
				log.Printf("[兼容模式] 已过滤不支持的节点类型 '%s': %s", proxyType, name)
				sb.WriteString(fmt.Sprintf("# 已跳过 %s: %s(兼容模式)\n", proxyType, name))
				continue
			}
		}

		line, reason := p.formatProxyLine(proxy)
		if line == "" {
			log.Printf("[Shadowrocket] 跳过节点 %s (%s): %s", name, proxyType, reason)
			sb.WriteString(fmt.Sprintf("# 已跳过 %s: %s(%s)\n", proxyType, name, reason))
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
		outputNames[name] = true
		outputOrder = append(outputOrder, name)
	}

	return sb.String(), outputNames, outputOrder
}

// formatProxyLine 把节点写成 Shadowrocket 配置文件里的本地节点:
//
//	节点名称=类型,地址,端口,参数=值,...
//
// 语法与参数名以 Shadowrocket 官方手册(github.com/LOWERTOP/Shadowrocket「编写本地节点」)为准,
// 手册没列的参数沿用 Shadowrocket 自己的分享链接参数(peer / xtls / pbk / sid / obfsParam / path),
// 两者是同一套解析。写不出来时返回空串和原因。
func (p *ShadowrocketTemplateProducer) formatProxyLine(proxy Proxy) (string, string) {
	proxyType := GetString(proxy, "type")
	name := GetString(proxy, "name")
	server := GetString(proxy, "server")
	port := GetInt(proxy, "port")

	if name == "" || server == "" || port == 0 {
		return "", "缺少名称、地址或端口"
	}

	typ := proxyType
	var params []string
	add := func(k, v string) {
		if v != "" {
			params = append(params, k+"="+v)
		}
	}
	addUDP := func() {
		if GetBool(proxy, "udp") {
			params = append(params, "udp=1")
		}
	}

	switch proxyType {
	case "ss":
		add("method", GetString(proxy, "cipher"))
		add("password", GetString(proxy, "password"))
		switch plugin := GetString(proxy, "plugin"); plugin {
		case "":
		case "obfs", "simple-obfs":
			if po := GetMap(proxy, "plugin-opts"); po != nil {
				add("obfs", GetString(po, "mode"))
				add("obfs-host", GetString(po, "host"))
			}
		case "v2ray-plugin":
			po := GetMap(proxy, "plugin-opts")
			if po == nil || GetString(po, "mode") != "websocket" {
				return "", "v2ray-plugin 只支持 websocket 模式"
			}
			params = append(params, "obfs=websocket")
			add("path", GetString(po, "path"))
			add("obfsParam", GetString(po, "host"))
			if GetBool(po, "tls") {
				params = append(params, "tls=true")
				add("peer", GetString(po, "host"))
				if GetBool(po, "skip-cert-verify") {
					params = append(params, "allowInsecure=1")
				}
			}
		default:
			return "", "不支持插件 " + plugin
		}
		addUDP()

	case "vmess":
		add("password", GetString(proxy, "uuid"))
		cipher := GetString(proxy, "cipher")
		if cipher == "" {
			cipher = "auto"
		}
		add("method", cipher)
		params = append(params, fmt.Sprintf("alterId=%d", GetInt(proxy, "alterId")))
		srConfTLS(proxy, &params, GetBool(proxy, "tls"))
		srConfTransport(proxy, &params)
		addUDP()

	case "vless":
		add("password", GetString(proxy, "uuid"))
		srConfTLS(proxy, &params, GetBool(proxy, "tls"))
		switch flow := GetString(proxy, "flow"); flow {
		case "":
		case "xtls-rprx-vision":
			params = append(params, "xtls=2")
		default:
			return "", "不支持 flow " + flow
		}
		srConfTransport(proxy, &params)
		addUDP()

	case "trojan":
		add("password", GetString(proxy, "password"))
		srConfTLS(proxy, &params, true)
		srConfTransport(proxy, &params)
		addUDP()

	case "http", "https", "socks5", "socks":
		// 手册:节点名称=http,地址,端口,用户,密码(位置参数)
		tls := proxyType == "https" || GetBool(proxy, "tls")
		switch {
		case (proxyType == "http" || proxyType == "https") && tls:
			typ = "https"
		case proxyType == "http" || proxyType == "https":
			typ = "http"
		case tls:
			typ = "socks5-tls"
		default:
			typ = "socks5"
		}
		user, pass := GetString(proxy, "username"), GetString(proxy, "password")
		if user != "" || pass != "" {
			params = append(params, user, pass)
		}
		if tls && GetBool(proxy, "skip-cert-verify") {
			params = append(params, "skip-common-name-verify=true")
		}
		if typ == "socks5" || typ == "socks5-tls" {
			addUDP()
		}

	case "hysteria2":
		add("auth", GetString(proxy, "password"))
		if GetString(proxy, "obfs") != "" {
			add("obfsParam", GetString(proxy, "obfs-password"))
		}
		srConfTLS(proxy, &params, true)
		params = append(params, "udp=1")

	case "hysteria":
		add("auth", firstNonBlank(GetString(proxy, "auth-str"), GetString(proxy, "auth_str")))
		add("obfsParam", GetString(proxy, "obfs"))
		add("protocol", GetString(proxy, "protocol"))
		if up := srMbps(proxy, "up"); up > 0 {
			params = append(params, fmt.Sprintf("upmbps=%d", up))
		}
		if down := srMbps(proxy, "down"); down > 0 {
			params = append(params, fmt.Sprintf("downmbps=%d", down))
		}
		srConfTLS(proxy, &params, true)
		params = append(params, "udp=1")

	case "tuic":
		if GetString(proxy, "token") != "" && GetString(proxy, "uuid") == "" {
			return "", "不支持 TUIC v4"
		}
		add("password", GetString(proxy, "password"))
		add("user", GetString(proxy, "uuid"))
		srConfTLS(proxy, &params, true)
		params = append(params, "udp=1")

	case "anytls":
		add("password", GetString(proxy, "password"))
		srConfTLS(proxy, &params, true)
		addUDP()

	case "snell":
		if obfs := GetMap(proxy, "obfs-opts"); obfs != nil && GetString(obfs, "mode") == "shadow-tls" {
			return "", "配置文件写不了 ShadowTLS"
		}
		add("password", GetString(proxy, "psk"))
		if v := GetInt(proxy, "version"); v > 0 {
			params = append(params, fmt.Sprintf("version=%d", v))
		}
		if obfs := GetMap(proxy, "obfs-opts"); obfs != nil {
			add("obfs", GetString(obfs, "mode"))
			add("obfs-host", GetString(obfs, "host"))
		}
		addUDP()

	case "wireguard":
		if peers, ok := proxy["peers"].([]interface{}); ok && len(peers) > 1 {
			return "", "不支持多个 peer"
		}
		if GetString(proxy, "preshared-key") != "" {
			return "", "配置文件写不了 pre-shared-key"
		}
		add("privateKey", GetString(proxy, "private-key"))
		add("publicKey", GetString(proxy, "public-key"))
		add("ip", GetString(proxy, "ip"))
		params = append(params, "udp=1")
		if dns := srStrings(proxy, "dns"); len(dns) > 0 {
			add("dns", dns[0])
		}
		if mtu := GetInt(proxy, "mtu"); mtu > 0 {
			params = append(params, fmt.Sprintf("mtu=%d", mtu))
		}
		if ka := GetInt(proxy, "keepalive"); ka > 0 {
			params = append(params, fmt.Sprintf("keepalive=%d", ka))
		}
		add("reserved", srWireGuardReserved(proxy["reserved"]))

	default:
		return "", "Shadowrocket 配置文件不支持此类型"
	}

	if GetBool(proxy, "tfo") || GetBool(proxy, "fast-open") {
		params = append(params, "tfo=1")
	}

	return fmt.Sprintf("%s=%s,%s,%d", name, typ, server, port) + srJoinParams(params), ""
}

func srJoinParams(params []string) string {
	if len(params) == 0 {
		return ""
	}
	return "," + strings.Join(params, ",")
}

// srConfTLS 写 TLS 相关参数。tls 为 false 时什么都不写;tls=true 只有 vmess / vless 要写
// (手册里 trojan / hysteria2 / tuic 本身就是 TLS,不带这个参数)。
// SNI 在 Shadowrocket 里叫 peer;跳过证书校验是 allowInsecure=1;REALITY 是 pbk / sid。
func srConfTLS(proxy Proxy, params *[]string, tls bool) {
	if !tls {
		return
	}
	if t := GetString(proxy, "type"); t == "vmess" || t == "vless" {
		*params = append(*params, "tls=true")
	}
	if sni := firstNonBlank(GetString(proxy, "servername"), GetString(proxy, "sni")); sni != "" {
		*params = append(*params, "peer="+sni)
	}
	if GetBool(proxy, "skip-cert-verify") {
		*params = append(*params, "allowInsecure=1")
	}
	// 多个 ALPN 要用逗号分隔,会和参数分隔符冲突,只在单个时写
	if alpn := srStrings(proxy, "alpn"); len(alpn) == 1 {
		*params = append(*params, "alpn="+alpn[0])
	}
	if fp := GetString(proxy, "client-fingerprint"); fp != "" {
		*params = append(*params, "fp="+fp)
	}
	if reality := GetMap(proxy, "reality-opts"); reality != nil {
		if pbk := GetString(reality, "public-key"); pbk != "" {
			*params = append(*params, "pbk="+pbk)
		}
		if sid := GetString(reality, "short-id"); sid != "" {
			*params = append(*params, "sid="+sid)
		}
	}
}

// srConfTransport 写传输层:obfs=websocket / grpc / h2 / http / xhttp,路径用 path(gRPC 是服务名),
// Host 用 obfsParam。
func srConfTransport(proxy Proxy, params *[]string) {
	set := func(obfs, path, host string) {
		*params = append(*params, "obfs="+obfs)
		if path != "" {
			*params = append(*params, "path="+path)
		}
		if host != "" {
			*params = append(*params, "obfsParam="+host)
		}
	}
	switch GetString(proxy, "network") {
	case "ws":
		opts := GetMap(proxy, "ws-opts")
		if opts == nil {
			set("websocket", "", "")
			return
		}
		host := ""
		if headers := GetMap(opts, "headers"); headers != nil {
			host = firstNonBlank(GetString(headers, "Host"), GetString(headers, "host"))
		}
		set("websocket", GetString(opts, "path"), host)
	case "grpc":
		opts := GetMap(proxy, "grpc-opts")
		path := ""
		if opts != nil {
			path = GetString(opts, "grpc-service-name")
		}
		set("grpc", path, "")
	case "h2":
		opts := GetMap(proxy, "h2-opts")
		path, host := "", ""
		if opts != nil {
			path = GetString(opts, "path")
			if hosts := srStrings(opts, "host"); len(hosts) > 0 {
				host = hosts[0]
			}
		}
		set("h2", path, host)
	case "http":
		opts := GetMap(proxy, "http-opts")
		path, host := "", ""
		if opts != nil {
			if paths := srStrings(opts, "path"); len(paths) > 0 {
				path = paths[0]
			}
			if headers := GetMap(opts, "headers"); headers != nil {
				if hosts := srStrings(headers, "Host"); len(hosts) > 0 {
					host = hosts[0]
				}
			}
		}
		set("http", path, host)
	case "xhttp", "splithttp":
		// transformProxies 已把路径 / Host 提到 path / obfsParam
		set("xhttp", GetString(proxy, "path"), GetString(proxy, "obfsParam"))
	}
}

// srMbps 取 hysteria 的 up / down(可能写成 "100 Mbps"),只留数字部分。
func srMbps(proxy Proxy, key string) int {
	if n := GetInt(proxy, key); n > 0 {
		return n
	}
	s := strings.TrimSpace(GetString(proxy, key))
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

// srWireGuardReserved 把 reserved([1,2,3] 或 "1,2,3")写成 Shadowrocket 的 1/2/3。
func srWireGuardReserved(v interface{}) string {
	var parts []string
	switch r := v.(type) {
	case []interface{}:
		for _, x := range r {
			parts = append(parts, strings.TrimSpace(fmt.Sprint(x)))
		}
	case []int:
		for _, x := range r {
			parts = append(parts, strconv.Itoa(x))
		}
	case string:
		for _, x := range strings.Split(r, ",") {
			if x = strings.TrimSpace(x); x != "" {
				parts = append(parts, x)
			}
		}
	}
	return strings.Join(parts, "/")
}

// srStrings 取字符串列表;单个字符串(alpn: h3、host: a.com)也当成一项。
func srStrings(m map[string]interface{}, key string) []string {
	if s, ok := m[key].(string); ok {
		if s = strings.TrimSpace(s); s != "" {
			return []string{s}
		}
		return nil
	}
	return GetStringSlice(m, key)
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// shadowrocketProxyGroups 取完整配置里的 proxy-groups(只要映射形式的条目)
func shadowrocketProxyGroups(fullConfig map[string]interface{}) []map[string]interface{} {
	var groups []map[string]interface{}
	if proxyGroups, ok := fullConfig["proxy-groups"].([]interface{}); ok {
		for _, group := range proxyGroups {
			if groupMap, ok := group.(map[string]interface{}); ok {
				groups = append(groups, groupMap)
			}
		}
	}
	return groups
}

// srProxyGroup 是展开后的代理组。
type srProxyGroup struct {
	raw     map[string]interface{}
	name    string
	members []string
	// regex 非空表示 filter 用了 Go 正则不认的写法(如前瞻),原样交给 Shadowrocket 的 policy-regex-filter 去筛
	regex string
	// empty 表示组确定没有任何成员(或类型写不出来),整组删除,引用它的地方一并清理
	empty bool
}

// srExpandProxyGroups 把 mihomo 运行时才取节点的写法展开成显式成员:
// include-all / include-all-proxies 取全部输出了的节点,再按 filter / exclude-filter / exclude-type 筛。
// Shadowrocket 配置里没有 include-all;不展开的话这类组没有成员、整组不输出,
// 规则里指向它的地方就全悬空了。use(proxy-providers)的节点不在订阅里,取不到。
func srExpandProxyGroups(groups []map[string]interface{}, outputOrder []string) []srProxyGroup {
	result := make([]srProxyGroup, 0, len(groups))
	for _, g := range groups {
		sg := srProxyGroup{raw: g, name: GetString(g, "name")}
		sg.members = append(sg.members, GetStringSlice(g, "proxies")...)

		if GetString(g, "type") == "relay" {
			log.Printf("[Shadowrocket] relay类型不支持，跳过: %s", sg.name)
			sg.empty = true
			result = append(result, sg)
			continue
		}

		if GetBool(g, "include-all") || GetBool(g, "include-all-proxies") {
			nodes, regex := srFilterNodes(outputOrder, g)
			sg.regex = regex
			seen := make(map[string]bool, len(sg.members))
			for _, m := range sg.members {
				seen[m] = true
			}
			for _, n := range nodes {
				if !seen[n] {
					sg.members = append(sg.members, n)
				}
			}
		}
		sg.empty = len(sg.members) == 0 && sg.regex == ""
		result = append(result, sg)
	}
	return result
}

// srFilterNodes 按组的 filter / exclude-filter 筛节点(mihomo 里多个表达式用反引号分隔,满足任一即可)。
// filter 编译不过时(mihomo 用的 regexp2 支持前瞻,Go 正则不支持)不展开,返回原式交给 Shadowrocket。
func srFilterNodes(names []string, g map[string]interface{}) ([]string, string) {
	compile := func(expr string) ([]*regexp.Regexp, bool) {
		var res []*regexp.Regexp
		for _, part := range strings.Split(expr, "`") {
			if part == "" {
				continue
			}
			re, err := regexp.Compile(part)
			if err != nil {
				return nil, false
			}
			res = append(res, re)
		}
		return res, true
	}
	matchAny := func(res []*regexp.Regexp, s string) bool {
		for _, re := range res {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}

	filter := GetString(g, "filter")
	include, ok := compile(filter)
	if !ok {
		return nil, filter
	}
	exclude, _ := compile(GetString(g, "exclude-filter"))

	var out []string
	for _, n := range names {
		if len(include) > 0 && !matchAny(include, n) {
			continue
		}
		if matchAny(exclude, n) {
			continue
		}
		out = append(out, n)
	}
	return out, ""
}

// generateProxyGroups 生成 [Proxy Group] 部分。pruned 与 groups 一一对应:
// 被删掉的组整组不输出,其余组用剔除悬空名字后的成员。
func (p *ShadowrocketTemplateProducer) generateProxyGroups(groups []srProxyGroup, pruned *policyPruneResult) string {
	var sb strings.Builder
	sb.WriteString("[Proxy Group]\n")
	sb.WriteString("# 代理分组\n")

	for i, g := range groups {
		if pruned.Removed[g.name] {
			continue
		}
		if line := p.formatProxyGroupLine(g, pruned.Members[i]); line != "" {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// formatProxyGroupLine 格式化代理组行:名称 = 类型,成员...,参数=值
func (p *ShadowrocketTemplateProducer) formatProxyGroupLine(g srProxyGroup, members []string) string {
	groupType := GetString(g.raw, "type")
	if g.name == "" || groupType == "" {
		return ""
	}
	switch groupType {
	case "select", "url-test", "fallback", "load-balance", "random":
	case "smart":
		groupType = "url-test"
	default:
		groupType = "select"
	}

	parts := []string{groupType}
	parts = append(parts, members...)
	if g.regex != "" {
		parts = append(parts, "policy-regex-filter="+g.regex)
	}
	if len(parts) == 1 {
		return ""
	}

	// 添加测试参数（仅 url-test, fallback, load-balance）
	if groupType == "url-test" || groupType == "fallback" || groupType == "load-balance" {
		if url := GetString(g.raw, "url"); url != "" {
			parts = append(parts, fmt.Sprintf("url=%s", url))
		} else {
			parts = append(parts, "url=http://www.gstatic.com/generate_204")
		}

		if interval := GetInt(g.raw, "interval"); interval > 0 {
			parts = append(parts, fmt.Sprintf("interval=%d", interval))
		}

		// mihomo 的 timeout 是毫秒,Shadowrocket 是秒
		timeout := GetInt(g.raw, "timeout")
		if timeout >= 100 {
			timeout /= 1000
		}
		if timeout <= 0 {
			timeout = 5
		}
		parts = append(parts, fmt.Sprintf("timeout=%d", timeout))

		if tolerance := GetInt(g.raw, "tolerance"); tolerance > 0 {
			parts = append(parts, fmt.Sprintf("tolerance=%d", tolerance))
		}
	}
	if GetBool(g.raw, "hidden") {
		parts = append(parts, "hidden=1")
	}

	return g.name + " = " + strings.Join(parts, ",")
}

// generateRules 生成 [Rule] 部分。目标策略悬空(dangling)的规则改成 DIRECT。
func (p *ShadowrocketTemplateProducer) generateRules(opts *ProduceOptions, dangling func(string) bool) string {
	var sb strings.Builder
	sb.WriteString("[Rule]\n")
	sb.WriteString("# 规则配置\n")

	// 处理 rule-providers（需要先处理，因为规则中会引用）
	ruleProviders := make(map[string]string)
	if providers, ok := opts.FullConfig["rule-providers"].(map[string]interface{}); ok {
		for name, provider := range providers {
			if providerMap, ok := provider.(map[string]interface{}); ok {
				if url := GetString(providerMap, "url"); url != "" {
					// 将 .mrs 转换为 .list
					convertedURL := strings.Replace(url, ".mrs", ".list", 1)
					ruleProviders[name] = convertedURL
				}
			}
		}
	}

	// 处理 rules
	if rules, ok := opts.FullConfig["rules"].([]interface{}); ok {
		for _, rule := range rules {
			if ruleStr, ok := rule.(string); ok {
				ruleLine := rewriteDanglingRulePolicy(p.formatRuleLine(ruleStr, ruleProviders), dangling)
				if ruleLine != "" {
					sb.WriteString(ruleLine)
					sb.WriteString("\n")
				}
			}
		}
	}

	// 如果没有规则，添加默认规则
	if len(sb.String()) < 50 {
		sb.WriteString("GEOIP,CN,DIRECT\n")
		sb.WriteString(rewriteDanglingRulePolicy("FINAL,PROXY", dangling) + "\n")
	}

	return sb.String()
}

// formatRuleLine 格式化规则行
func (p *ShadowrocketTemplateProducer) formatRuleLine(rule string, ruleProviders map[string]string) string {
	parts := strings.Split(rule, ",")
	if len(parts) < 2 {
		return ""
	}

	ruleType := strings.TrimSpace(parts[0])

	// RULE-SET 特殊处理
	if ruleType == "RULE-SET" && len(parts) >= 3 {
		ruleSetName := strings.TrimSpace(parts[1])
		policy := strings.TrimSpace(parts[2])

		// 查找对应的 URL
		if url, ok := ruleProviders[ruleSetName]; ok {
			return fmt.Sprintf("RULE-SET,%s,%s", url, policy)
		}

		log.Printf("[Shadowrocket] 找不到规则集: %s", ruleSetName)
		return fmt.Sprintf("# 规则集未找到: %s", rule)
	}

	// MATCH -> FINAL
	if ruleType == "MATCH" {
		if len(parts) >= 2 {
			return fmt.Sprintf("FINAL,%s", strings.TrimSpace(parts[1]))
		}
		return "FINAL,PROXY"
	}

	// 其他规则直接返回
	return rule
}

// generateHost 生成 [Host] 部分
func (p *ShadowrocketTemplateProducer) generateHost() string {
	return "[Host]\nlocalhost = 127.0.0.1"
}

// transformProxies 转换节点（完整的旧版逻辑）
func (p *ShadowrocketTemplateProducer) transformProxies(proxies []Proxy, opts *ProduceOptions) []Proxy {
	supportedVMessCiphers := map[string]bool{
		"auto": true, "none": true, "zero": true,
		"aes-128-gcm": true, "chacha20-poly1305": true,
	}

	var result []Proxy
	for _, proxy := range proxies {
		proxyType := p.helper.GetProxyType(proxy)

		// Filter unsupported types
		if !opts.IncludeUnsupportedProxy {
			// 与非模板版同一套规则:Shadowrocket 支持 Snell v1–v6。这里以前把 v4 以上整个丢掉,
			// 绑了模板的订阅里 Snell v4 / v5 / v6 节点全部消失。
			if !srSupportsSnellVersion(proxy) || srSnellShadowTLSObfsConflict(proxy) {
				continue
			}
			if proxyType == "mieru" {
				continue
			}
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
			// Keepalive / preshared key:只在非零 / 非空时输出(见 normalizeWireGuardOptionalFields)
			normalizeWireGuardOptionalFields(transformed)
		}

		// Snell transformations
		if proxyType == "snell" {
			srTransformSnell(transformed)
		}

		// VLESS transformations
		if proxyType == "vless" {
			// SNI -> servername
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
				if IsPresent(httpOpts, "path") {
					if path, ok := httpOpts["path"].(string); ok {
						httpOpts["path"] = []string{path}
					}
				}

				// Ensure headers.Host is array
				if headers := GetMap(httpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						headers["Host"] = []string{host}
					}
				}
			}
		}

		// 处理xhttp参数
		if proxyType == "vless" && network == "xhttp" {
			if xhttpOpts := GetMap(transformed, "xhttp-opts"); xhttpOpts != nil {
				transformed["obfs"] = network
				if path, ok := xhttpOpts["path"].(string); ok {
					transformed["path"] = path
				}

				if headers := GetMap(xhttpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						transformed["obfsParam"] = host
					}
				}
			}
		}

		// 兼容0.3.7后续版本xhttp改为splithttp的情况
		if proxyType == "vless" && (network == "splithttp" || network == "xhttp") {
			transformed["network"] = "xhttp"
			transformed["obfs"] = "xhttp"
			if splithttpOpts := GetMap(transformed, "splithttp-opts"); splithttpOpts != nil {
				if path, ok := splithttpOpts["path"].(string); ok {
					transformed["path"] = path
				}

				if headers := GetMap(splithttpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						transformed["obfsParam"] = host
					}
				}
			} else if xhttpOpts := GetMap(transformed, "xhttp-opts"); xhttpOpts != nil {
				if path, ok := xhttpOpts["path"].(string); ok {
					transformed["path"] = path
				}

				if headers := GetMap(xhttpOpts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						transformed["obfsParam"] = host
					}
				}
			}
		}

		// Handle H2 network options
		if (proxyType == "vmess" || proxyType == "vless") && network == "h2" {
			if h2Opts := GetMap(transformed, "h2-opts"); h2Opts != nil {
				// Ensure path is string (take first element if array)
				if pathSlice, ok := h2Opts["path"].([]interface{}); ok && len(pathSlice) > 0 {
					h2Opts["path"] = pathSlice[0]
				}

				// Ensure host is array
				if headers := GetMap(h2Opts, "headers"); headers != nil {
					if host, ok := headers["Host"].(string); ok {
						headers["host"] = []string{host}
					}
				}
			}
		}

		// Handle plugin-opts TLS
		if pluginOpts := GetMap(transformed, "plugin-opts"); pluginOpts != nil {
			if GetBool(pluginOpts, "tls") && IsPresent(transformed, "skip-cert-verify") {
				pluginOpts["skip-cert-verify"] = GetBool(transformed, "skip-cert-verify")
			}
		}

		// Clean up fields
		p.helper.RemoveProxyFields(transformed,
			"subName", "collectionName", "id", "resolved", "no-resolve")

		// Remove null and underscore-prefixed fields
		for key := range transformed {
			if transformed[key] == nil || strings.HasPrefix(key, "_") {
				delete(transformed, key)
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

	return result
}
