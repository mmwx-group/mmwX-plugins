package substore

import (
	"testing"
)

// srInternal 运行 Shadowrocket producer 的 internal 输出, 返回首个 transform 后的 proxy。
// internal 输出为 []Proxy, 便于逐字段断言。filtered=false 表示该节点被过滤掉。
func srInternal(t *testing.T, proxy Proxy) (Proxy, bool) {
	t.Helper()
	out, err := NewShadowrocketProducer().Produce([]Proxy{proxy}, "internal", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list, ok := out.([]Proxy)
	if !ok {
		t.Fatalf("expected []Proxy, got %T", out)
	}
	if len(list) == 0 {
		return nil, false
	}
	return list[0], true
}

// 对齐 JS: proxy.cipher = normalizeVmessSecurity(proxy.cipher) —— 无条件归一化。
func TestShadowrocketVmessCipherNormalize(t *testing.T) {
	got, ok := srInternal(t, Proxy{
		"name": "v", "type": "vmess", "server": "a.com", "port": 443,
		"uuid": "id", "cipher": "chacha20-ietf-poly1305",
	})
	if !ok {
		t.Fatal("vmess unexpectedly filtered")
	}
	if c := GetString(got, "cipher"); c != "chacha20-poly1305" {
		t.Errorf("cipher 别名未归一: got %q want chacha20-poly1305", c)
	}

	// cipher 缺失也应被设为 auto
	got2, _ := srInternal(t, Proxy{
		"name": "v2", "type": "vmess", "server": "a.com", "port": 443, "uuid": "id",
	})
	if c := GetString(got2, "cipher"); c != "auto" {
		t.Errorf("cipher 缺失未回退 auto: got %q", c)
	}
}

// 对齐 JS normalizeWebSocketEarlyDataPath: ?ed=N 从 path 提取为 max-early-data。
func TestShadowrocketWsEarlyData(t *testing.T) {
	got, ok := srInternal(t, Proxy{
		"name": "v", "type": "vmess", "server": "a.com", "port": 443, "uuid": "id",
		"network": "ws",
		"ws-opts": map[string]interface{}{"path": "/p?ed=2048"},
	})
	if !ok {
		t.Fatal("vmess ws unexpectedly filtered")
	}
	wsOpts := GetMap(got, "ws-opts")
	if wsOpts == nil {
		t.Fatal("ws-opts missing")
	}
	if p := GetString(wsOpts, "path"); p != "/p" {
		t.Errorf("path 未剥离 ed 参数: got %q want /p", p)
	}
	if GetInt(wsOpts, "max-early-data") != 2048 {
		t.Errorf("max-early-data 未设置: %v", wsOpts["max-early-data"])
	}
	if GetString(wsOpts, "early-data-header-name") != "Sec-WebSocket-Protocol" {
		t.Errorf("early-data-header-name 未设置: %v", wsOpts["early-data-header-name"])
	}
}

// 对齐 JS: snell 仅支持 version 1..5, 其余过滤。
func TestShadowrocketSnellVersionFilter(t *testing.T) {
	if _, ok := srInternal(t, Proxy{
		"name": "s", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 6,
	}); ok {
		t.Error("snell version 6 应被过滤")
	}
	if _, ok := srInternal(t, Proxy{
		"name": "s", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 3,
	}); !ok {
		t.Error("snell version 3 不应被过滤")
	}
}

// 对齐 JS deleteTLSTypes: trusttunnel 应删除 tls 字段。
func TestShadowrocketTrusttunnelDeletesTLS(t *testing.T) {
	got, ok := srInternal(t, Proxy{
		"name": "tt", "type": "trusttunnel", "server": "a.com", "port": 443, "tls": true,
	})
	if !ok {
		t.Fatal("trusttunnel unexpectedly filtered")
	}
	if IsPresent(got, "tls") {
		t.Errorf("trusttunnel 的 tls 字段应被删除, 仍存在: %v", got["tls"])
	}
}

// 对齐 JS H2: headers.Host 迁移到 h2-opts.host(数组), 并删除 headers.Host。
func TestShadowrocketH2HostMigrate(t *testing.T) {
	got, ok := srInternal(t, Proxy{
		"name": "v", "type": "vmess", "server": "a.com", "port": 443, "uuid": "id",
		"network": "h2",
		"h2-opts": map[string]interface{}{
			"path":    "/h2",
			"headers": map[string]interface{}{"Host": "bing.com"},
		},
	})
	if !ok {
		t.Fatal("vmess h2 unexpectedly filtered")
	}
	h2 := GetMap(got, "h2-opts")
	if h2 == nil {
		t.Fatal("h2-opts missing")
	}
	host, isSlice := h2["host"].([]interface{})
	if !isSlice || len(host) == 0 || host[0] != "bing.com" {
		t.Errorf("h2-opts.host 未迁移为数组: %#v", h2["host"])
	}
	if headers := GetMap(h2, "headers"); headers != nil {
		if IsPresent(headers, "Host") {
			t.Errorf("headers.Host 应被删除: %v", headers["Host"])
		}
	}
}
