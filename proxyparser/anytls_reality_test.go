package proxyparser

import "testing"

// AnyTLS + REALITY 只有 sing-box 支持, mihomo 官方声明不支持该组合且不打算支持。
// Sub-Store 的 URI_AnyTLS 借 VLESS 解析器解出 reality-opts, 并在存在 reality-opts
// 时刻意保留 network="tcp" —— 下游 clashmeta/stash/loon 靠这个标记剔除该节点。
func TestParseAnytlsURLWithReality(t *testing.T) {
	uri := "anytls://passw0rd@38.1.2.3:20000?sni=www.example.com&fp=chrome" +
		"&security=reality&pbk=0WxD-SzAKKrjqiubZJ3o&sid=e1f7bbf1#AnyTLS-REALITY"
	node, err := Parse(uri)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	subset(t, "anytls+reality", node, map[string]any{
		"type":               "anytls",
		"server":             "38.1.2.3",
		"port":               20000,
		"password":           "passw0rd",
		"name":               "AnyTLS-REALITY",
		"sni":                "www.example.com",
		"client-fingerprint": "chrome",
		"network":            "tcp",
		"reality-opts": map[string]any{
			"public-key": "0WxD-SzAKKrjqiubZJ3o",
			"short-id":   "e1f7bbf1",
		},
	})
}

// 普通 AnyTLS 节点不应带上 network/security 标记, 否则会被下游误判并剔除。
func TestParseAnytlsURLWithoutRealityHasNoNetworkMarker(t *testing.T) {
	uri := "anytls://passw0rd@38.1.2.3:20000?sni=www.example.com&fp=chrome#AnyTLS"
	node, err := Parse(uri)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, ok := node["network"]; ok {
		t.Errorf("普通 AnyTLS 不应带 network 标记, got=%v", node["network"])
	}
	if _, ok := node["security"]; ok {
		t.Errorf("普通 AnyTLS 不应带 security 标记, got=%v", node["security"])
	}
	if _, ok := node["reality-opts"]; ok {
		t.Errorf("普通 AnyTLS 不应有 reality-opts")
	}
	subset(t, "anytls", node, map[string]any{
		"type": "anytls", "sni": "www.example.com", "client-fingerprint": "chrome",
	})
}
