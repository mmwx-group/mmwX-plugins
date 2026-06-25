package substore

import (
	"strings"
	"testing"
)

// produceStashInternal 运行 Stash producer 并以 internal 形式返回转换后的节点列表,
// 方便逐字段断言(避免解析最终 YAML 文本)。
func produceStashInternal(t *testing.T, proxy Proxy, opts *ProduceOptions) Proxy {
	t.Helper()
	out, err := NewStashProducer().Produce([]Proxy{proxy}, "internal", opts)
	if err != nil {
		t.Fatalf("Produce 出错: %v", err)
	}
	list, ok := out.([]Proxy)
	if !ok {
		t.Fatalf("internal 输出类型应为 []Proxy, 实际 %T", out)
	}
	if len(list) != 1 {
		t.Fatalf("期望 1 个节点, 实际 %d 个(可能被过滤)", len(list))
	}
	return list[0]
}

func produceStashCount(t *testing.T, proxies []Proxy, opts *ProduceOptions) int {
	t.Helper()
	out, err := NewStashProducer().Produce(proxies, "internal", opts)
	if err != nil {
		t.Fatalf("Produce 出错: %v", err)
	}
	if out == nil {
		return 0
	}
	return len(out.([]Proxy))
}

// 新增支持类型: tailscale / trusttunnel 应被保留。
func TestStashSupportsTailscaleAndTrusttunnel(t *testing.T) {
	proxies := []Proxy{
		{"name": "ts", "type": "tailscale", "server": "1.1.1.1", "port": 443},
		{"name": "tt", "type": "trusttunnel", "server": "2.2.2.2", "port": 443},
	}
	if got := produceStashCount(t, proxies, &ProduceOptions{}); got != 2 {
		t.Fatalf("tailscale/trusttunnel 应被保留, 期望 2, 实际 %d", got)
	}
}

// trusttunnel 应删除 tls 字段(进入 delete-tls 列表)。
func TestStashTrusttunnelDeletesTLS(t *testing.T) {
	got := produceStashInternal(t, Proxy{
		"name": "tt", "type": "trusttunnel", "server": "2.2.2.2", "port": 443, "tls": true,
	}, &ProduceOptions{})
	if IsPresent(got, "tls") {
		t.Fatalf("trusttunnel 的 tls 字段应被删除, 实际仍存在: %v", got["tls"])
	}
}

// underlying-proxy 应转换为 dialer-proxy 且原字段被删除。
func TestStashUnderlyingProxyToDialerProxy(t *testing.T) {
	got := produceStashInternal(t, Proxy{
		"name": "n", "type": "trojan", "server": "a.com", "port": 443,
		"underlying-proxy": "前置组",
	}, &ProduceOptions{})
	if v := GetString(got, "dialer-proxy"); v != "前置组" {
		t.Fatalf("dialer-proxy 期望=前置组, 实际=%q", v)
	}
	if IsPresent(got, "underlying-proxy") {
		t.Fatalf("underlying-proxy 应被删除, 实际仍存在")
	}
}

// vless + reality-opts: network=tcp 保留, network=ws 跳过。
func TestStashVlessRealityNetworkFilter(t *testing.T) {
	tcp := []Proxy{{
		"name": "v", "type": "vless", "server": "a.com", "port": 443,
		"reality-opts": map[string]interface{}{"public-key": "x"}, "network": "tcp",
	}}
	if produceStashCount(t, tcp, &ProduceOptions{}) != 1 {
		t.Fatalf("vless+reality+tcp 应保留")
	}
	ws := []Proxy{{
		"name": "v", "type": "vless", "server": "a.com", "port": 443,
		"reality-opts": map[string]interface{}{"public-key": "x"}, "network": "ws",
	}}
	if produceStashCount(t, ws, &ProduceOptions{}) != 0 {
		t.Fatalf("vless+reality+ws 应被跳过")
	}
}

// anytls: 无 network 保留; network=grpc 跳过; tcp+reality 跳过。
func TestStashAnytlsNetworkFilter(t *testing.T) {
	base := func(extra map[string]interface{}) []Proxy {
		p := Proxy{"name": "a", "type": "anytls", "server": "a.com", "port": 443}
		for k, v := range extra {
			p[k] = v
		}
		return []Proxy{p}
	}
	if produceStashCount(t, base(nil), &ProduceOptions{}) != 1 {
		t.Fatalf("anytls 无 network 应保留")
	}
	if produceStashCount(t, base(map[string]interface{}{"network": "grpc"}), &ProduceOptions{}) != 0 {
		t.Fatalf("anytls network=grpc 应被跳过")
	}
	if produceStashCount(t, base(map[string]interface{}{
		"network": "tcp", "reality-opts": map[string]interface{}{"public-key": "x"},
	}), &ProduceOptions{}) != 0 {
		t.Fatalf("anytls tcp+reality 应被跳过")
	}
}

// SS v2ray-plugin: websocket 模式保留, 非 websocket 模式跳过。
func TestStashSSV2rayPluginModeFilter(t *testing.T) {
	ws := []Proxy{{
		"name": "s", "type": "ss", "server": "a.com", "port": 443,
		"cipher": "aes-128-gcm", "plugin": "v2ray-plugin",
		"plugin-opts": map[string]interface{}{"mode": "websocket"},
	}}
	if produceStashCount(t, ws, &ProduceOptions{}) != 1 {
		t.Fatalf("SS v2ray-plugin websocket 应保留")
	}
	quic := []Proxy{{
		"name": "s", "type": "ss", "server": "a.com", "port": 443,
		"cipher": "aes-128-gcm", "plugin": "v2ray-plugin",
		"plugin-opts": map[string]interface{}{"mode": "quic"},
	}}
	if produceStashCount(t, quic, &ProduceOptions{}) != 0 {
		t.Fatalf("SS v2ray-plugin quic 应被跳过")
	}
}

// include-unsupported-proxy 开启时绕过所有过滤(如本不支持的 ssh? 实际 ssh 支持,
// 用 snell v4 这种确定会被过滤的节点验证放行)。
func TestStashIncludeUnsupportedBypassesFilter(t *testing.T) {
	snellV4 := []Proxy{{
		"name": "sn", "type": "snell", "server": "a.com", "port": 443, "version": 4,
	}}
	if produceStashCount(t, snellV4, &ProduceOptions{}) != 0 {
		t.Fatalf("默认情况下 snell v4 应被跳过")
	}
	if produceStashCount(t, snellV4, &ProduceOptions{IncludeUnsupportedProxy: true}) != 1 {
		t.Fatalf("include-unsupported-proxy 开启时 snell v4 应被放行")
	}
}

// vmess cipher 规范化: chacha20-ietf-poly1305 -> chacha20-poly1305, 不支持值回退 auto。
func TestStashVmessCipherNormalize(t *testing.T) {
	got := produceStashInternal(t, Proxy{
		"name": "v", "type": "vmess", "server": "a.com", "port": 443,
		"uuid": "u", "cipher": "CHACHA20-IETF-POLY1305",
	}, &ProduceOptions{})
	if c := GetString(got, "cipher"); c != "chacha20-poly1305" {
		t.Fatalf("cipher 期望=chacha20-poly1305, 实际=%q", c)
	}

	got2 := produceStashInternal(t, Proxy{
		"name": "v", "type": "vmess", "server": "a.com", "port": 443,
		"uuid": "u", "cipher": "rc4",
	}, &ProduceOptions{})
	if c := GetString(got2, "cipher"); c != "auto" {
		t.Fatalf("不支持的 cipher 应回退 auto, 实际=%q", c)
	}
}

// ws 早期数据: path 中的 ?ed=2048 应被提取为 max-early-data, path 清理干净。
func TestStashWSEarlyData(t *testing.T) {
	got := produceStashInternal(t, Proxy{
		"name": "w", "type": "vmess", "server": "a.com", "port": 443, "uuid": "u",
		"network": "ws",
		"ws-opts": map[string]interface{}{"path": "/abc?ed=2048"},
	}, &ProduceOptions{})
	wsOpts := GetMap(got, "ws-opts")
	if wsOpts == nil {
		t.Fatalf("ws-opts 缺失")
	}
	if p := GetString(wsOpts, "path"); p != "/abc" {
		t.Fatalf("path 应清理为 /abc, 实际=%q", p)
	}
	if GetInt(wsOpts, "max-early-data") != 2048 {
		t.Fatalf("max-early-data 应为 2048, 实际=%v", wsOpts["max-early-data"])
	}
	if GetString(wsOpts, "early-data-header-name") != "Sec-WebSocket-Protocol" {
		t.Fatalf("early-data-header-name 应为 Sec-WebSocket-Protocol")
	}
}

// ws + v2ray-http-upgrade 应被过滤跳过。
func TestStashWSV2rayHTTPUpgradeFilter(t *testing.T) {
	p := []Proxy{{
		"name": "w", "type": "vmess", "server": "a.com", "port": 443, "uuid": "u",
		"network": "ws",
		"ws-opts": map[string]interface{}{"v2ray-http-upgrade": true},
	}}
	if produceStashCount(t, p, &ProduceOptions{}) != 0 {
		t.Fatalf("ws+v2ray-http-upgrade 应被跳过")
	}
}

// h2 host 规范化: 来自 headers.Host 的值应提升到顶层 h2-opts.host 数组, headers 被清空删除。
func TestStashH2HostNormalize(t *testing.T) {
	got := produceStashInternal(t, Proxy{
		"name": "h", "type": "vmess", "server": "a.com", "port": 443, "uuid": "u",
		"network": "h2",
		"h2-opts": map[string]interface{}{
			"path":    []interface{}{"/p1", "/p2"},
			"headers": map[string]interface{}{"Host": "example.com"},
		},
	}, &ProduceOptions{})
	h2 := GetMap(got, "h2-opts")
	if h2 == nil {
		t.Fatalf("h2-opts 缺失")
	}
	// path 数组应取第一个元素
	if p, ok := h2["path"].(string); !ok || p != "/p1" {
		t.Fatalf("h2 path 应取数组首元素 /p1, 实际=%v", h2["path"])
	}
	host, ok := h2["host"].([]interface{})
	if !ok || len(host) != 1 || host[0] != "example.com" {
		t.Fatalf("h2 host 应为 [example.com], 实际=%v", h2["host"])
	}
	if IsPresent(h2, "headers") {
		t.Fatalf("headers 清空后应被删除, 实际仍存在: %v", h2["headers"])
	}
}

// ip-cidr / ipv6-cidr 字段应被删除。
func TestStashRemovesIPCidrFields(t *testing.T) {
	got := produceStashInternal(t, Proxy{
		"name": "n", "type": "ss", "server": "a.com", "port": 443, "cipher": "aes-128-gcm",
		"password": "p", "ip-cidr": "10.0.0.0/8", "ipv6-cidr": "::/0",
	}, &ProduceOptions{})
	if IsPresent(got, "ip-cidr") || IsPresent(got, "ipv6-cidr") {
		t.Fatalf("ip-cidr/ipv6-cidr 应被删除")
	}
}

// 全量配置输出应包含转换后的 dialer-proxy 字段(端到端 smoke)。
func TestStashFullConfigContainsDialerProxy(t *testing.T) {
	out, err := NewStashProducer().Produce([]Proxy{{
		"name": "n", "type": "trojan", "server": "a.com", "port": 443,
		"underlying-proxy": "G",
	}}, "stash", &ProduceOptions{})
	if err != nil {
		t.Fatalf("Produce 出错: %v", err)
	}
	text, ok := out.(string)
	if !ok {
		t.Fatalf("stash 输出应为字符串, 实际 %T", out)
	}
	if !strings.Contains(text, "dialer-proxy") {
		t.Fatalf("全量配置应包含 dialer-proxy 字段")
	}
}
