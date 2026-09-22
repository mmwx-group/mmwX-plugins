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

// t=surge 走 Produce:dialer-proxy 指向没输出的节点(WG / VLESS 等)时不能写 underlying-proxy,
// 否则 [Proxy] 里引用一个不存在的策略,Surge 拒载。指向已输出节点或不认识的名字(模板里的
// 策略组)照常写。
func TestSurgeProduceDropsDanglingUnderlyingProxy(t *testing.T) {
	trojan := func(name, dialer string) Proxy {
		p := Proxy{"name": name, "type": "trojan", "server": "5.6.7.8", "port": 443, "password": "pw"}
		if dialer != "" {
			p["dialer-proxy"] = dialer
		}
		return p
	}
	proxies := []Proxy{
		masterWireGuardProxy(),
		{"name": "vl", "type": "vless", "server": "5.6.7.8", "port": 443, "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		trojan("via-wg", "wg-in"),
		trojan("via-vl", "vl"),
		trojan("relay", ""),
		trojan("via-relay", "relay"),
		trojan("via-group", "RELAY-GROUP"),
	}
	out, err := NewSurgeProducer().Produce(proxies, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out.(string)), "\n") {
		lines[strings.SplitN(line, "=", 2)[0]] = line
	}
	if len(lines) != 5 {
		t.Fatalf("应输出 5 个 trojan 节点,得到:\n%s", out)
	}
	for name, want := range map[string]string{"via-wg": "", "via-vl": "", "relay": "", "via-relay": "relay", "via-group": "RELAY-GROUP"} {
		line := lines[name]
		has := strings.Contains(line, "underlying-proxy")
		if want == "" && has {
			t.Errorf("%s 不应带悬空的 underlying-proxy:\n%s", name, line)
		}
		if want != "" && !strings.HasSuffix(line, ", underlying-proxy="+want) {
			t.Errorf("%s 应带 underlying-proxy=%s:\n%s", name, want, line)
		}
	}
}
