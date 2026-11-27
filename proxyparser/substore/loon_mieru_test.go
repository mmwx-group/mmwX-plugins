package substore

import (
	"strings"
	"testing"
)

// 上游 Sub-Store 85948dcf(2026-11-23)的 Loon Mieru 期望输出(text.spec.js 的 Loon Mieru 用例)。
func TestLoonMieruUpstream85948dcf(t *testing.T) {
	p := NewLoonProducer()
	base := func(extra Proxy) Proxy {
		proxy := Proxy{"type": "mieru", "name": "Mieru", "server": "example.com", "port": 8443, "username": "user", "password": "pass"}
		for k, v := range extra {
			proxy[k] = v
		}
		return proxy
	}
	cases := []struct {
		proxy Proxy
		want  string
	}{
		// 用户名密码一律加引号(带逗号、空白也原样保留),IPv6 加方括号
		{base(Proxy{"server": "2001:db8::1", "username": " user,name ", "password": " pass,word ", "transport": "TCP", "udp": true,
			"block-quic": "off", "ip-version": "ipv4-prefer", "server-dns": []interface{}{"system", "2001:db8::53"}}),
			`Mieru=mieru,[2001:db8::1],8443," user,name "," pass,word ",udp=true,block-quic=false,ip-mode=prefer-v4,server-dns="system,2001:db8::53"`},
		// udp 为 false 时不写
		{base(Proxy{"udp": false}), `Mieru=mieru,example.com,8443,"user","pass"`},
		// 服务器地址去首尾空白
		{base(Proxy{"server": " example.com "}), `Mieru=mieru,example.com,8443,"user","pass"`},
		{base(Proxy{"server": " 2001:db8::1 "}), `Mieru=mieru,[2001:db8::1],8443,"user","pass"`},
		// transport 大小写不敏感;Loon 没有的 multiplexing / handshake-mode / mtu / traffic-pattern 不输出
		{base(Proxy{"transport": "tcp", "multiplexing": "MULTIPLEXING_LOW", "handshake-mode": "HANDSHAKE_NO_WAIT", "mtu": 1400, "traffic-pattern": "xyz", "block-quic": "on"}),
			`Mieru=mieru,example.com,8443,"user","pass",block-quic=true`},
		// 端口:JSON 数字(float64)、字符串都认,边界 1 / 65535
		{base(Proxy{"port": float64(1)}), `Mieru=mieru,example.com,1,"user","pass"`},
		{base(Proxy{"port": "65535"}), `Mieru=mieru,example.com,65535,"user","pass"`},
		// 用户名、密码按 UTF-8 字节数算,恰好 64 字节可以
		{base(Proxy{"username": strings.Repeat("密", 21) + "a", "password": strings.Repeat("🔒", 16)}),
			`Mieru=mieru,example.com,8443,"` + strings.Repeat("密", 21) + `a","` + strings.Repeat("🔒", 16) + `"`},
	}
	for _, c := range cases {
		got, err := p.ProduceOne(c.proxy, "", nil)
		if err != nil {
			t.Fatalf("%v: %v", c.proxy, err)
		}
		if got != c.want {
			t.Fatalf("\n got  %s\n want %s", got, c.want)
		}
	}
}

// 端口范围节点:妙妙屋X 下发前删掉了 port、只留 port-range。Loon 只有单端口,取范围的第一个;
// port 还在时以 port 为准。
func TestLoonMieruPortRange(t *testing.T) {
	p := NewLoonProducer()
	for _, c := range []struct {
		proxy Proxy
		want  string
	}{
		{Proxy{"type": "mieru", "name": "ranged", "server": "1.2.3.4", "port-range": "20000-20100", "username": "a", "password": "b", "transport": "TCP"},
			`ranged=mieru,1.2.3.4,20000,"a","b"`},
		{Proxy{"type": "mieru", "name": "multi", "server": "1.2.3.4", "port-range": "20000-20100,30000-30010", "username": "a", "password": "b"},
			`multi=mieru,1.2.3.4,20000,"a","b"`},
		{Proxy{"type": "mieru", "name": "both", "server": "1.2.3.4", "port": 20050, "port-range": "20000-20100", "username": "a", "password": "b"},
			`both=mieru,1.2.3.4,20050,"a","b"`},
	} {
		got, err := p.ProduceOne(c.proxy, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", c.proxy["name"], err)
		}
		if got != c.want {
			t.Fatalf("\n got  %s\n want %s", got, c.want)
		}
	}
}

// Loon 不支持的 Mieru:UDP 传输、TLS / REALITY、缺服务器、端口不合法、凭据为空或超过 64 字节、
// 凭据里有双引号 —— 跳过而不是输出一行 Loon 读不了的。
func TestLoonMieruUnsupported(t *testing.T) {
	p := NewLoonProducer()
	base := Proxy{"type": "mieru", "name": "Mieru", "server": "example.com", "port": 8443, "username": "user", "password": "pass"}
	for _, c := range []struct {
		extra Proxy
		want  string
	}{
		{Proxy{"transport": "UDP"}, "TCP transport"},
		{Proxy{"tls": true}, "TLS or REALITY"},
		{Proxy{"reality-opts": map[string]interface{}{"public-key": "x"}}, "TLS or REALITY"},
		{Proxy{"server": ""}, "requires a server"},
		{Proxy{"server": "\t "}, "requires a server"},
		{Proxy{"port": 0}, "from 1 to 65535"},
		{Proxy{"port": 65536}, "from 1 to 65535"},
		{Proxy{"port": 443.5}, "from 1 to 65535"},
		{Proxy{"port": "0x1bb"}, "from 1 to 65535"},
		{Proxy{"port": "+443"}, "from 1 to 65535"},
		{Proxy{"port": nil}, "from 1 to 65535"},
		{Proxy{"username": ""}, "1-64 UTF-8 bytes"},
		{Proxy{"password": ""}, "1-64 UTF-8 bytes"},
		{Proxy{"username": strings.Repeat("密", 22)}, "1-64 UTF-8 bytes"},
		{Proxy{"password": strings.Repeat("a", 65)}, "1-64 UTF-8 bytes"},
		{Proxy{"password": `pa"ss`}, "unsupported characters"},
	} {
		proxy := Proxy{}
		for k, v := range base {
			proxy[k] = v
		}
		for k, v := range c.extra {
			if v == nil {
				delete(proxy, k)
			} else {
				proxy[k] = v
			}
		}
		out, err := p.ProduceOne(proxy, "", nil)
		if err == nil {
			t.Fatalf("%v 应跳过, 得到 %s", c.extra, out)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%v: 错误 %q 应包含 %q", c.extra, err, c.want)
		}
	}
}

// 完整配置(可莉版 / 模板注入)走的是同一个 ProduceOne,Mieru 节点要进 [Proxy] 段,也能进策略组。
func TestLoonConfigKeepsMieru(t *testing.T) {
	proxies := []Proxy{
		{"type": "mieru", "name": "M1", "server": "1.2.3.4", "port": 2999, "username": "a", "password": "b", "transport": "TCP", "udp": true},
		{"type": "mieru", "name": "M-UDP", "server": "1.2.3.4", "port": 2999, "username": "a", "password": "b", "transport": "UDP"},
	}
	lines, _, err := BuildLoonProxySections(proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lines != `M1=mieru,1.2.3.4,2999,"a","b",udp=true` {
		t.Fatalf("[Proxy] 段: %q", lines)
	}
	cfg, err := BuildLoonKeleeConfig(proxies)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "\n"+`M1=mieru,1.2.3.4,2999,"a","b",udp=true`+"\n") {
		t.Fatalf("可莉版配置里没有 Mieru 节点:\n%s", cfg)
	}
	if strings.Contains(cfg, "M-UDP=") {
		t.Fatalf("UDP 传输的 Mieru 不该输出:\n%s", cfg)
	}
}
