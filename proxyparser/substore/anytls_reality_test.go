package substore

import (
	"encoding/json"
	"strings"
	"testing"
)

func singboxOutbound(t *testing.T, proxies []Proxy) map[string]interface{} {
	t.Helper()
	prod, err := GetDefaultFactory().GetProducer("sing-box")
	if err != nil {
		t.Fatalf("取 sing-box producer: %v", err)
	}
	raw, err := prod.Produce(proxies, "", nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	var cfg struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(raw.(string)), &cfg); err != nil {
		t.Fatalf("解析 sing-box 输出: %v", err)
	}
	if len(cfg.Outbounds) == 0 {
		return nil
	}
	return cfg.Outbounds[0]
}

// AnyTLS+REALITY 只有 sing-box 支持: clashmeta/stash/loon 必须剔除, sing-box 必须下发。
// 依赖解析层保留的 network="tcp" 标记, 见 Sub-Store clashmeta.js / stash.js 的过滤条件。
func TestAnytlsRealityOnlyReachesSingbox(t *testing.T) {
	proxy := Proxy{
		"name": "n", "type": "anytls", "server": "38.1.2.3", "port": 20000,
		"password": "pw", "sni": "www.example.com", "network": "tcp",
		"reality-opts": map[string]any{"public-key": "PBKPBK", "short-id": "SIDSID"},
	}
	for _, tc := range []struct {
		producer string
		wantKept bool
	}{
		{"clashmeta", false},
		{"stash", false},
		{"loon", false},
		{"sing-box", true},
	} {
		prod, err := GetDefaultFactory().GetProducer(tc.producer)
		if err != nil {
			t.Fatalf("取 %s producer: %v", tc.producer, err)
		}
		raw, err := prod.Produce([]Proxy{proxy}, "", nil)
		if err != nil {
			t.Fatalf("%s produce: %v", tc.producer, err)
		}
		out, _ := raw.(string)
		kept := strings.Contains(strings.ToLower(out), "anytls")
		if kept != tc.wantKept {
			t.Errorf("%s: 下发节点=%v, 期望 %v\n输出: %s", tc.producer, kept, tc.wantKept, out)
		}
	}
}

// sing-box 必须把 reality/utls 落进 tls 块, 且 server_name 取 sni 而非 server。
func TestSingboxAnytlsRealityOutput(t *testing.T) {
	ob := singboxOutbound(t, []Proxy{{
		"name": "n", "type": "anytls", "server": "38.1.2.3", "port": 20000,
		"password": "pw", "sni": "www.example.com", "network": "tcp",
		"client-fingerprint": "chrome",
		"reality-opts":       map[string]any{"public-key": "PBKPBK", "short-id": "SIDSID"},
	}})
	if ob == nil {
		t.Fatal("sing-box 未输出任何 outbound")
	}
	tls, ok := ob["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("缺少 tls 块: %v", ob)
	}
	if got := tls["server_name"]; got != "www.example.com" {
		t.Errorf("server_name = %v, 期望 sni www.example.com", got)
	}
	reality, ok := tls["reality"].(map[string]interface{})
	if !ok {
		t.Fatalf("缺少 tls.reality: %v", tls)
	}
	if reality["public_key"] != "PBKPBK" || reality["short_id"] != "SIDSID" {
		t.Errorf("reality = %v, 期望 public_key=PBKPBK short_id=SIDSID", reality)
	}
	if _, ok := tls["utls"].(map[string]interface{}); !ok {
		t.Errorf("REALITY 必须同时开启 utls, got tls=%v", tls)
	}
}

// 回归: 天生走 TLS 的协议在 Clash 表示里不带 tls 字段, 且 ClashMeta 中间层会 delete
// proxy.tls。tlsParser 若从 enabled:false 重新构造, 这些协议的 sni/alpn/insecure
// 会被整块丢弃, server_name 退化成 server 地址 —— server 填 IP 时即为静默握手故障。
func TestSingboxKeepsSniForImplicitTLSProtocols(t *testing.T) {
	for _, tc := range []struct {
		typ   string
		extra Proxy
	}{
		{"anytls", Proxy{"password": "pw"}},
		{"trojan", Proxy{"password": "pw"}},
		{"hysteria2", Proxy{"password": "pw"}},
		{"tuic", Proxy{"uuid": "u", "password": "pw"}},
		{"naive", Proxy{"username": "u", "password": "pw"}},
	} {
		proxy := Proxy{
			"name": "n", "type": tc.typ, "server": "1.2.3.4", "port": 443,
			"sni": "cdn.example.com", "skip-cert-verify": true,
		}
		for k, v := range tc.extra {
			proxy[k] = v
		}
		ob := singboxOutbound(t, []Proxy{proxy})
		if ob == nil {
			t.Errorf("%s: sing-box 未输出", tc.typ)
			continue
		}
		tls, ok := ob["tls"].(map[string]interface{})
		if !ok {
			t.Errorf("%s: 缺少 tls 块", tc.typ)
			continue
		}
		if got := tls["server_name"]; got != "cdn.example.com" {
			t.Errorf("%s: server_name = %v, 期望 sni cdn.example.com", tc.typ, got)
		}
		// naive 的 sing-box 出站不支持 tls.insecure, naiveParser 会显式删除它。
		if tc.typ == "naive" {
			if _, ok := tls["insecure"]; ok {
				t.Errorf("naive 不应带 tls.insecure, got=%v", tls["insecure"])
			}
			continue
		}
		if got := tls["insecure"]; got != true {
			t.Errorf("%s: insecure = %v, 期望 skip-cert-verify 生效为 true", tc.typ, got)
		}
	}
}
