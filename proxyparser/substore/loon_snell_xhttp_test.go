package substore

import (
	"strings"
	"testing"
)

// 上游 Sub-Store 92ea17c8(2026-11-19)的 Loon Snell 期望输出(text.spec.js「emits Loon Snell」)。
func TestLoonSnellUpstream92ea17c8(t *testing.T) {
	p := NewLoonProducer()
	cases := []struct {
		proxy Proxy
		want  string
	}{
		{Proxy{"type": "snell", "name": "Surge v4", "server": "example.com", "port": 6160, "psk": "secret", "version": 4, "udp": true, "block-quic": "off"},
			`Surge v4=snell,example.com,6160,"secret",version=4,udp=true,block-quic=false`},
		{Proxy{"type": "snell", "name": "Loon v4", "server": "example.com", "port": 6160, "psk": "key,with=comma", "version": 4, "udp": false},
			`Loon v4=snell,example.com,6160,"key,with=comma",version=4,udp=false`},
		{Proxy{"type": "snell", "name": "Loon v5", "server": "example.com", "port": 6161, "psk": "secret", "version": 5,
			"obfs-opts": map[string]interface{}{"mode": "http", "host": "cdn.example.com", "path": "/a,b?c=d"},
			"udp": true, "block-quic": "off", "ip-version": "ipv4-prefer", "server-dns": []interface{}{"system", "2001:db8::53"}},
			`Loon v5=snell,example.com,6161,"secret",version=5,obfs=http,obfs-host=cdn.example.com,obfs-uri="/a,b?c=d",udp=true,block-quic=false,ip-mode=prefer-v4,server-dns="system,2001:db8::53"`},
		{Proxy{"type": "snell", "name": "Loon block", "server": "example.com", "port": 6161, "psk": "secret", "version": 5, "udp": false, "block-quic": "on"},
			`Loon block=snell,example.com,6161,"secret",version=5,udp=false,block-quic=true`},
		// 面板生成的 Snell 节点:version 是 JSON 数字(float64),没有 udp 字段时不输出
		{Proxy{"type": "snell", "name": "[AgentB] snell-1", "server": "1.2.3.4", "port": float64(8888), "psk": "abc", "version": float64(5)},
			`[AgentB] snell-1=snell,1.2.3.4,8888,"abc",version=5`},
	}
	for _, c := range cases {
		got, err := p.ProduceOne(c.proxy, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", c.proxy["name"], err)
		}
		if got != c.want {
			t.Fatalf("%s:\n got  %s\n want %s", c.proxy["name"], got, c.want)
		}
	}
}

// Loon 不认的 Snell:v1–v3 / v6、非 http 混淆(shadow-tls、tls)、没有 psk —— 跳过而不是输出一行 Loon 读不了的。
func TestLoonSnellUnsupported(t *testing.T) {
	p := NewLoonProducer()
	for _, proxy := range []Proxy{
		{"type": "snell", "name": "v3", "server": "a", "port": 1, "psk": "x", "version": 3},
		{"type": "snell", "name": "v6", "server": "a", "port": 1, "psk": "x", "version": 6},
		{"type": "snell", "name": "noversion", "server": "a", "port": 1, "psk": "x"},
		{"type": "snell", "name": "tls-obfs", "server": "a", "port": 1, "psk": "x", "version": 4, "obfs-opts": map[string]interface{}{"mode": "tls"}},
		{"type": "snell", "name": "stls", "server": "a", "port": 1, "psk": "x", "version": 4, "obfs-opts": map[string]interface{}{"mode": "shadow-tls"}},
		{"type": "snell", "name": "nopsk", "server": "a", "port": 1, "version": 4},
	} {
		if out, err := p.ProduceOne(proxy, "", nil); err == nil {
			t.Fatalf("%s 应跳过, 得到 %s", proxy["name"], out)
		}
	}
	// 整份订阅里不支持的那条被跳过,别的照常输出
	out, err := p.Produce([]Proxy{
		{"type": "snell", "name": "ok", "server": "a", "port": 1, "psk": "x", "version": 4},
		{"type": "snell", "name": "v6", "server": "a", "port": 1, "psk": "x", "version": 6},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := out.(string); !strings.Contains(s, "ok=snell,") || strings.Contains(s, "v6=snell") {
		t.Fatalf("整份输出不对:\n%s", s)
	}
}

// XHTTP:VLESS / VMess(AEAD)/ Trojan(上游 92ea17c8 的 round-trip 用例,Go 只有 producer,按片段比)。
func TestLoonXhttpUpstream92ea17c8(t *testing.T) {
	p := NewLoonProducer()
	const uuid = "0f6f1d0e-3f45-4c1e-9b32-2f0b5c9a7e11"

	vless, err := p.ProduceOne(Proxy{
		"type": "vless", "name": "VLESS", "server": "example.com", "port": 80, "uuid": uuid,
		"network": "xhttp", "tls": false, "udp": true, "alpn": []interface{}{"http/1.1"},
		"xhttp-opts": map[string]interface{}{
			"path": "/xhttp?route=a,b", "host": "cdn.example.com", "mode": "packet-up",
			"sc-max-each-post-bytes": float64(0), "sc-min-posts-interval-ms": "30-60",
			"x-padding-obfs-mode": false, "session-table": "Base62", "session-length": "16-32",
			"headers": map[string]interface{}{"X-Trace": "a, b", "X-Origin": "https://example.org"},
		},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`VLESS=vless,example.com,80,"` + uuid + `"`,
		`,transport=xhttp,path="/xhttp?route=a,b",host=cdn.example.com`,
		`,xhttp-mode=packet-up`, `,xhttp-min-post-interval-ms=30-60`, `,xhttp-max-post-bytes=0`,
		`,xhttp-padding-obfs-mode=false`, `,xhttp-session-id-table=Base62`, `,xhttp-session-id-length=16-32`,
		`,xhttp-header="X-Origin: https://example.org"`, `,xhttp-header="X-Trace: a, b"`,
		`,over-tls=false`, `alpn`, `,udp=true`,
	} {
		if !strings.Contains(vless, want) {
			t.Fatalf("VLESS 缺 %s:\n%s", want, vless)
		}
	}
	if strings.Contains(vless, "transport=tcp") {
		t.Fatalf("XHTTP 不该再写 transport=tcp:\n%s", vless)
	}

	vmess, err := p.ProduceOne(Proxy{
		"type": "vmess", "name": "VMess", "server": "example.com", "port": 443, "uuid": uuid, "cipher": "aes-128-gcm",
		"network": "xhttp", "tls": true, "servername": "cdn.example.com", "alterId": 0,
		"xhttp-opts": map[string]interface{}{"path": "/xhttp?username=test", "mode": "stream-up", "no-grpc-header": true},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{",transport=xhttp,path=/xhttp?username=test", ",xhttp-mode=stream-up", ",xhttp-no-grpc-header=true", ",sni=cdn.example.com", ",alterId=0"} {
		if !strings.Contains(vmess, want) {
			t.Fatalf("VMess 缺 %s:\n%s", want, vmess)
		}
	}
	if strings.Contains(vmess, "tls-name=") {
		t.Fatalf("XHTTP 下应写 sni= 而不是 tls-name=:\n%s", vmess)
	}

	trojan, err := p.ProduceOne(Proxy{
		"type": "trojan", "name": "Trojan", "server": "example.com", "port": 443, "password": "dGVzdA==",
		"network": "xhttp", "sni": "cdn.example.com", "xhttp-opts": map[string]interface{}{"mode": "stream-one"},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{",transport=xhttp", ",xhttp-mode=stream-one", ",sni=cdn.example.com"} {
		if !strings.Contains(trojan, want) {
			t.Fatalf("Trojan 缺 %s:\n%s", want, trojan)
		}
	}
}

func TestLoonXhttpUnsupported(t *testing.T) {
	p := NewLoonProducer()
	for _, proxy := range []Proxy{
		// 非 AEAD 的 VMess
		{"type": "vmess", "name": "a", "server": "s", "port": 1, "uuid": "u", "network": "xhttp", "alterId": 1},
		// VLESS XHTTP 不能带 flow
		{"type": "vless", "name": "b", "server": "s", "port": 1, "uuid": "u", "network": "xhttp", "flow": "xtls-rprx-vision"},
		// 下行分离
		{"type": "vless", "name": "c", "server": "s", "port": 1, "uuid": "u", "network": "xhttp",
			"xhttp-opts": map[string]interface{}{"download-settings": map[string]interface{}{"server": "d"}}},
		// 选项里有双引号写不进 Loon 的一行
		{"type": "vless", "name": "d", "server": "s", "port": 1, "uuid": "u", "network": "xhttp",
			"xhttp-opts": map[string]interface{}{"path": `/a"b`}},
	} {
		if out, err := p.ProduceOne(proxy, "", nil); err == nil {
			t.Fatalf("%s 应跳过, 得到 %s", proxy["name"], out)
		}
	}
}
