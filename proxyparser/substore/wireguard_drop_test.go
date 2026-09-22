package substore

import (
	"strings"
	"testing"
)

func dropTestProxies() []Proxy {
	return []Proxy{
		{
			"name": "tj", "type": "trojan", "server": "1.2.3.4", "port": 443,
			"password": "pw", "sni": "a.example.com",
		},
		masterWireGuardProxy(),
	}
}

// 不支持 WG 的格式:主控从不设 IncludeUnsupportedProxy,WG 节点必须被干净地剔掉 ——
// 不报错、不留坏行、不输出带字面 `\n` 的 [WireGuard] 段,其它节点照常输出。
func TestUnsupportedFormatsDropWireGuardCleanly(t *testing.T) {
	cases := []struct {
		name     string
		producer Producer
		wantLine string
	}{
		{"surfboard", NewSurfboardProducer(), "tj=trojan,1.2.3.4,443"},
		{"surge", NewSurgeProducer(), "tj=trojan,1.2.3.4,443"},
		{"surgemac", NewSurgeMacProducer(), "tj=trojan,1.2.3.4,443"},
		{"qx", NewQXProducer(), "trojan=1.2.3.4:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.producer.Produce(dropTestProxies(), "", nil)
			if err != nil {
				t.Fatalf("有一个 WG 节点就整份失败: %v", err)
			}
			got, _ := out.(string)
			lines := strings.Split(strings.TrimSpace(got), "\n")
			if len(lines) != 1 || !strings.Contains(lines[0], tc.wantLine) {
				t.Fatalf("应只输出 trojan 一行,得到:\n%s", got)
			}
			for _, bad := range []string{"wg-in", "wireguard", "WireGuard", `\n`, "private-key"} {
				if strings.Contains(got, bad) {
					t.Errorf("输出里不应出现 %q:\n%s", bad, got)
				}
			}
		})
	}
}

// Surfboard 的错误分支以前写反了:IncludeUnsupportedProxy=false 时直接 return err。
// 对 vless 等其它不支持的类型也一样,不只是 WG。
func TestSurfboardSkipsAnyUnsupportedProxy(t *testing.T) {
	proxies := append(dropTestProxies(), Proxy{
		"name": "vl", "type": "vless", "server": "5.6.7.8", "port": 443,
		"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	})
	for _, opts := range []*ProduceOptions{nil, {}, {IncludeUnsupportedProxy: true}} {
		out, err := NewSurfboardProducer().Produce(proxies, "", opts)
		if err != nil {
			t.Fatalf("opts=%+v: 不应返回错误: %v", opts, err)
		}
		if got := out.(string); !strings.HasPrefix(got, "tj=trojan,") || strings.Contains(got, "\n") {
			t.Errorf("opts=%+v: 应只输出 trojan,得到:\n%s", opts, got)
		}
	}
}
