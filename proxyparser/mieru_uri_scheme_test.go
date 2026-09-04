package proxyparser

import "testing"

// 官方 mieru 客户端导出的链接:scheme 带 s、端口在 query 里、传输协议叫 protocol。
// 三处任一没处理都会让节点导不进来或连不上(#115)。
func TestParseMieruOfficialExportURI(t *testing.T) {
	const uri = "mierus://r2RYIiZSxS:GuoNTOfndr@116.126.122.66" +
		"?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_OFF" +
		"&port=11211&profile=default&protocol=TCP"

	node, err := Parse(uri)
	if err != nil {
		t.Fatalf("官方导出的 mierus:// 链接解析失败: %v", err)
	}
	for _, tc := range []struct {
		key  string
		want any
		why  string
	}{
		{"type", "mieru", ""},
		{"server", "116.126.122.66", ""},
		{"port", 11211, "端口在 query 里,host 段没带 —— 取不到就会是 0,节点连不上"},
		{"username", "r2RYIiZSxS", ""},
		{"password", "GuoNTOfndr", ""},
		{"transport", "TCP", "官方链接里叫 protocol;不能把 handshake-mode 当传输方式"},
		{"multiplexing", "MULTIPLEXING_OFF", ""},
		{"mtu", 1400, ""},
	} {
		if got := node[tc.key]; got != tc.want {
			t.Errorf("%s = %v(%T),期望 %v。%s", tc.key, got, got, tc.want, tc.why)
		}
	}
}

// 老写法(mieru:// + host 带端口)不能被改坏:host 段的端口比 query 更具体,以它为准。
func TestParseMieruLegacyURIStillWorks(t *testing.T) {
	node, err := Parse("mieru://alice:s3cret@example.com:2999?transport=UDP&port=11211#我的节点")
	if err != nil {
		t.Fatalf("mieru:// 老写法解析失败: %v", err)
	}
	if node["port"] != 2999 {
		t.Errorf("port = %v,期望 2999 —— host 段写了端口就不该被 query 覆盖", node["port"])
	}
	if node["transport"] != "UDP" {
		t.Errorf("transport = %v,期望 UDP", node["transport"])
	}
	if node["name"] != "我的节点" {
		t.Errorf("name = %v", node["name"])
	}
}
