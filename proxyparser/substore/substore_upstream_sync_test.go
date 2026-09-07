package substore

import (
	"strings"
	"testing"
)

// Surge 自 2026-08-11 / 09-03(上游 536bb1cd / 6fff06f1)起支持 TrustTunnel 与 MASQUE。
// 这两个分支之前完全没有,节点会被当成「不支持的类型」丢出订阅。
func TestSurgeTrustTunnelAndMasque(t *testing.T) {
	t.Run("trusttunnel", func(t *testing.T) {
		out, err := NewSurgeProducer().ProduceOne(Proxy{
			"name": "tt", "type": "trusttunnel", "server": "1.2.3.4", "port": 443,
			"username": "u", "password": "pw", "network": "h3", "max-streams": 8,
		}, "", &ProduceOptions{})
		if err != nil {
			t.Fatalf("不该被拒: %v", err)
		}
		for _, want := range []string{"tt=trust-tunnel,1.2.3.4,443", `username="u"`, "max-streams=8", "h3=true"} {
			if !strings.Contains(out, want) {
				t.Fatalf("缺 %q,实际: %s", want, out)
			}
		}
	})
	t.Run("masque", func(t *testing.T) {
		out, err := NewSurgeProducer().ProduceOne(Proxy{
			"name": "mq", "type": "masque-surge", "server": "1.2.3.4", "port": 443,
			"username": "u", "password": "pw", "ports": "1000,2000",
		}, "", &ProduceOptions{})
		if err != nil {
			t.Fatalf("不该被拒: %v", err)
		}
		for _, want := range []string{"mq=masque,1.2.3.4,443", `password="pw"`, `port-hopping="1000;2000"`} {
			if !strings.Contains(out, want) {
				t.Fatalf("缺 %q,实际: %s", want, out)
			}
		}
	})
}

// Egern 自 2026-09-07(上游 df46feff)起支持 shadowsocksr。
// 只吃流加密 + 白名单里的 protocol/obfs,其余仍按上游过滤掉。
func TestEgernShadowsocksR(t *testing.T) {
	out, err := (&EgernProducer{}).Produce([]Proxy{{
		"name": "ssr1", "type": "ssr", "server": "1.2.3.4", "port": 8388,
		"cipher": "aes-128-cfb", "password": "pw",
		"protocol": "auth_aes128_md5", "protocol-param": "pp",
		"obfs": "tls1.2_ticket_auth", "obfs-param": "op",
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("SSR 不该被拒: %v", err)
	}
	got, _ := out.(string)
	for _, want := range []string{"shadowsocksr", "auth_aes128_md5", "protocol_param", "tls1.2_ticket_auth", "obfs_param"} {
		if !strings.Contains(got, want) {
			t.Fatalf("输出缺 %q,实际: %s", want, got)
		}
	}
}

// Egern 的 SSR 不支持 AEAD 加密,这类要被过滤掉(对齐上游 isEgernSsr)。
func TestEgernShadowsocksRRejectsAEAD(t *testing.T) {
	out, err := (&EgernProducer{}).Produce([]Proxy{{
		"name": "ssr-aead", "type": "ssr", "server": "1.2.3.4", "port": 8388,
		"cipher": "aes-128-gcm", "password": "pw",
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("不该整体报错: %v", err)
	}
	if strings.Contains(out.(string), "ssr-aead") {
		t.Fatalf("AEAD 加密的 SSR 应被过滤,实际: %s", out)
	}
}

// Shadowrocket 不支持 shadowquic / zerotier,要过滤掉而不是原样输出(上游 b63f6084 / 47ce75a4)。
func TestShadowrocketFiltersShadowQuicAndZeroTier(t *testing.T) {
	for _, typ := range []string{"shadowquic", "zerotier"} {
		out, err := NewShadowrocketProducer().Produce([]Proxy{{
			"name": "x-" + typ, "type": typ, "server": "1.2.3.4", "port": 443,
		}}, "", &ProduceOptions{})
		if err != nil {
			t.Fatalf("%s: 不该整体报错: %v", typ, err)
		}
		if s, _ := out.(string); strings.Contains(s, "x-"+typ) {
			t.Fatalf("%s 应被过滤,实际: %s", typ, s)
		}
	}
}

// Stash 自 2026-08-11(上游 0dc202e7)起支持 MASQUE;不在白名单会被静默丢掉。
func TestStashKeepsMasque(t *testing.T) {
	out, err := NewStashProducer().Produce([]Proxy{{
		"name": "mq", "type": "masque", "server": "1.2.3.4", "port": 443, "password": "pw",
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if !strings.Contains(out.(string), "mq") {
		t.Fatalf("MASQUE 节点不该被丢掉,实际: %s", out)
	}
}

// sing-box:AnyTLS 的 client_metadata 官方版就支持;client_name 只有非官方版认,
// 得挂在 include-unsupported-proxy 后面(上游 a4c8741d / 95958c85)。
func TestSingboxAnytlsClientFields(t *testing.T) {
	proxy := Proxy{
		"name": "a", "type": "anytls", "server": "1.2.3.4", "port": 443,
		"password": "pw", "client-metadata": "meta", "client-name": "cn",
	}
	official, err := NewSingboxProducer().Produce([]Proxy{proxy}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("官方版不该报错: %v", err)
	}
	s, _ := official.(string)
	if !strings.Contains(s, "client_metadata") {
		t.Fatalf("client_metadata 官方版就该输出,实际: %s", s)
	}
	if strings.Contains(s, "client_name") {
		t.Fatalf("client_name 只有非官方版认,官方版不该输出,实际: %s", s)
	}

	unofficial, err := NewSingboxProducer().Produce([]Proxy{proxy}, "", &ProduceOptions{IncludeUnsupportedProxy: true})
	if err != nil {
		t.Fatalf("非官方版不该报错: %v", err)
	}
	if !strings.Contains(unofficial.(string), "client_name") {
		t.Fatalf("开了 include-unsupported 应输出 client_name,实际: %s", unofficial)
	}
}

// sing-box HY2 的 bbr_profile / disable_chrome_parrot(上游 810ca5de)。
func TestSingboxHysteria2NewFields(t *testing.T) {
	out, err := NewSingboxProducer().Produce([]Proxy{{
		"name": "h", "type": "hysteria2", "server": "1.2.3.4", "port": 443,
		"password": "pw", "bbr-profile": "aggressive", "disable-chrome-parrot": true,
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	s, _ := out.(string)
	for _, want := range []string{"bbr_profile", "aggressive", "disable_chrome_parrot"} {
		if !strings.Contains(s, want) {
			t.Fatalf("缺 %q,实际: %s", want, s)
		}
	}
}
