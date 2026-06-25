package substore

import (
	"reflect"
	"testing"
)

// produceClashInternal 运行 Clash producer 并返回首个转换后的 Proxy(internal 输出)。
func produceClashInternal(t *testing.T, p Proxy) Proxy {
	t.Helper()
	out, err := NewClashProducer().Produce([]Proxy{p}, "internal", &ProduceOptions{})
	if err != nil {
		t.Fatalf("produce error: %v", err)
	}
	list, ok := out.([]Proxy)
	if !ok {
		t.Fatalf("unexpected output type %T", out)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(list))
	}
	return list[0]
}

// TestClashVmessCipherNormalizeAlias 验证 chacha20-ietf-poly1305 别名归一为 chacha20-poly1305。
func TestClashVmessCipherNormalizeAlias(t *testing.T) {
	got := clashNormalizeVmessSecurity("chacha20-ietf-poly1305")
	if got != "chacha20-poly1305" {
		t.Fatalf("alias normalize: got %q want chacha20-poly1305", got)
	}
}

// TestClashVmessCipherNormalizeTrimCase 验证大小写/空白规范化与回退。
func TestClashVmessCipherNormalizeTrimCase(t *testing.T) {
	cases := map[string]string{
		"  AES-128-GCM ": "aes-128-gcm",
		"AUTO":           "auto",
		"none":           "none",
		"":               "auto", // 缺失回退
		"rc4-md5":        "auto", // 不支持回退
	}
	for in, want := range cases {
		if got := clashNormalizeVmessSecurity(in); got != want {
			t.Errorf("normalize(%q): got %q want %q", in, got, want)
		}
	}
}

// TestClashVmessCipherAlwaysSet 验证即使 vmess 缺少 cipher 也会被设为 auto(无条件赋值)。
func TestClashVmessCipherAlwaysSet(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "vmess", "name": "a", "server": "s", "port": 443,
		"uuid": "u",
	})
	if out["cipher"] != "auto" {
		t.Fatalf("cipher: got %v want auto", out["cipher"])
	}
}

// TestClashWsEarlyDataFromEdParam 验证 ws path 中 ?ed= 被剥离并生成早数据字段。
func TestClashWsEarlyDataFromEdParam(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "vmess", "name": "a", "server": "s", "port": 443, "uuid": "u",
		"network": "ws",
		"ws-opts": map[string]interface{}{
			"path": "/path?ed=2048",
		},
	})
	ws, _ := out["ws-opts"].(map[string]interface{})
	if ws == nil {
		t.Fatal("ws-opts missing")
	}
	if ws["path"] != "/path" {
		t.Errorf("path: got %v want /path", ws["path"])
	}
	if ws["early-data-header-name"] != "Sec-WebSocket-Protocol" {
		t.Errorf("early-data-header-name: got %v", ws["early-data-header-name"])
	}
	if ws["max-early-data"] != 2048 {
		t.Errorf("max-early-data: got %v want 2048", ws["max-early-data"])
	}
}

// TestClashWsDefaultPath 验证缺省 ws path 被设为 "/" 且无早数据字段。
func TestClashWsDefaultPath(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "vmess", "name": "a", "server": "s", "port": 443, "uuid": "u",
		"network": "ws",
	})
	ws, _ := out["ws-opts"].(map[string]interface{})
	if ws == nil || ws["path"] != "/" {
		t.Fatalf("default ws path: got %v", out["ws-opts"])
	}
	if _, ok := ws["max-early-data"]; ok {
		t.Errorf("unexpected max-early-data on default path")
	}
}

// TestClashH2HostFromHeaders 验证 h2 host 从 headers.Host 迁移到 h2-opts.host(数组)并清空 headers。
func TestClashH2HostFromHeaders(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "vless", "name": "a", "server": "s", "port": 443, "uuid": "u",
		"network": "h2",
		"h2-opts": map[string]interface{}{
			"path":    []interface{}{"/p1", "/p2"},
			"headers": map[string]interface{}{"Host": "example.com"},
		},
	})
	h2, _ := out["h2-opts"].(map[string]interface{})
	if h2 == nil {
		t.Fatal("h2-opts missing")
	}
	if h2["path"] != "/p1" {
		t.Errorf("path: got %v want /p1", h2["path"])
	}
	host, ok := h2["host"].([]interface{})
	if !ok || !reflect.DeepEqual(host, []interface{}{"example.com"}) {
		t.Errorf("host: got %#v want [example.com]", h2["host"])
	}
	if _, ok := h2["headers"]; ok {
		t.Errorf("headers should be removed when emptied, got %v", h2["headers"])
	}
}

// TestClashTrusttunnelDeletesTLS 验证 trusttunnel 类型会删除 tls 字段。
func TestClashTrusttunnelDeletesTLS(t *testing.T) {
	out, err := NewClashProducer().Produce([]Proxy{{
		"type": "trusttunnel", "name": "a", "server": "s", "port": 443,
		"tls": "something",
	}}, "internal", &ProduceOptions{IncludeUnsupportedProxy: true})
	if err != nil {
		t.Fatalf("produce error: %v", err)
	}
	list := out.([]Proxy)
	if _, ok := list[0]["tls"]; ok {
		t.Errorf("tls should be deleted for trusttunnel")
	}
}

// TestClashDeletesIPCidrFields 验证 ip-cidr / ipv6-cidr 被删除。
func TestClashDeletesIPCidrFields(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "trojan", "name": "a", "server": "s", "port": 443, "password": "p",
		"ip-cidr": "1.2.3.4/32", "ipv6-cidr": "::/0",
	})
	if _, ok := out["ip-cidr"]; ok {
		t.Errorf("ip-cidr should be deleted")
	}
	if _, ok := out["ipv6-cidr"]; ok {
		t.Errorf("ipv6-cidr should be deleted")
	}
}

// TestClashPluginOptsSkipCertVerifyOr 验证 plugin-opts.skip-cert-verify 取 OR,不被 false 覆盖。
func TestClashPluginOptsSkipCertVerifyOr(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "ss", "name": "a", "server": "s", "port": 443,
		"cipher": "aes-128-gcm", "password": "p",
		"skip-cert-verify": false,
		"plugin-opts": map[string]interface{}{
			"tls":              true,
			"skip-cert-verify": true,
		},
	})
	po, _ := out["plugin-opts"].(map[string]interface{})
	if po == nil || po["skip-cert-verify"] != true {
		t.Fatalf("plugin-opts skip-cert-verify should stay true, got %v", out["plugin-opts"])
	}
}

// TestClashVlessFlowFiltered 验证带 flow 的 vless 被过滤(空串也算存在键)。
func TestClashVlessFlowFiltered(t *testing.T) {
	out, err := NewClashProducer().Produce([]Proxy{{
		"type": "vless", "name": "a", "server": "s", "port": 443, "uuid": "u",
		"flow": "",
	}}, "internal", &ProduceOptions{})
	if err != nil {
		t.Fatalf("produce error: %v", err)
	}
	if list := out.([]Proxy); len(list) != 0 {
		t.Errorf("vless with flow key should be filtered, got %d", len(list))
	}
}

// TestClashTlsFingerprintEmptyNotMigrated 验证空 tls-fingerprint 不迁移到 fingerprint。
func TestClashTlsFingerprintEmptyNotMigrated(t *testing.T) {
	out := produceClashInternal(t, Proxy{
		"type": "ss", "name": "a", "server": "s", "port": 443,
		"cipher": "aes-128-gcm", "password": "p",
		"tls-fingerprint": "",
	})
	if _, ok := out["fingerprint"]; ok {
		t.Errorf("empty tls-fingerprint should not produce fingerprint")
	}
	if _, ok := out["tls-fingerprint"]; ok {
		t.Errorf("tls-fingerprint should be deleted")
	}
}
