package substore

import (
	"strings"
	"testing"
)

func surfboardProduce(t *testing.T, proxy Proxy) string {
	t.Helper()
	p := NewSurfboardProducer()
	out, err := p.Produce([]Proxy{proxy}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := out.(string)
	if !ok {
		t.Fatalf("expected string output, got %T", out)
	}
	return s
}

func surfboardProduceErr(t *testing.T, proxy Proxy) error {
	t.Helper()
	p := NewSurfboardProducer()
	_, err := p.Produce([]Proxy{proxy}, "", nil)
	return err
}

func TestSurfboardHysteria2(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name":         "h2",
		"type":         "hysteria2",
		"server":       "example.com",
		"port":         443,
		"password":     "pass",
		"ports":        "1000,2000,3000",
		"hop-interval": 30,
		"down":         "100 Mbps",
		"udp":          true,
		"block-quic":   "on",
	})
	want := `h2=hysteria2,example.com,443,password="pass",port-hopping="1000;2000;3000",port-hopping-interval=30,download-bandwidth=100,udp-relay=true,block-quic=on`
	if got != want {
		t.Errorf("hysteria2 mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestSurfboardHysteria2ObfsRejected(t *testing.T) {
	err := surfboardProduceErr(t, Proxy{
		"name": "h2", "type": "hysteria2", "server": "e.com", "port": 443,
		"obfs": "salamander",
	})
	if err == nil || !strings.Contains(err.Error(), "obfs") {
		t.Errorf("expected obfs rejection, got %v", err)
	}
}

func TestSurfboardAnytls(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "a", "type": "anytls", "server": "e.com", "port": 8443,
		"password": "pw", "tfo": true, "udp": true, "reuse": true,
	})
	want := `a=anytls,e.com,8443,password="pw",tfo=true,udp-relay=true,reuse=true`
	if got != want {
		t.Errorf("anytls mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestSurfboardAnytlsRejectsNonTcpNetwork(t *testing.T) {
	err := surfboardProduceErr(t, Proxy{
		"name": "a", "type": "anytls", "server": "e.com", "port": 8443,
		"network": "ws",
	})
	if err == nil || !strings.Contains(err.Error(), "anytls") {
		t.Errorf("expected anytls network rejection, got %v", err)
	}
}

func TestSurfboardAnytlsRejectsTcpReality(t *testing.T) {
	err := surfboardProduceErr(t, Proxy{
		"name": "a", "type": "anytls", "server": "e.com", "port": 8443,
		"network":      "tcp",
		"reality-opts": map[string]interface{}{"public-key": "k"},
	})
	if err == nil || !strings.Contains(err.Error(), "REALITY") {
		t.Errorf("expected anytls reality rejection, got %v", err)
	}
}

func TestSurfboardSnellVersionGatesUdp(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "s", "type": "snell", "server": "e.com", "port": 6000,
		"version": 4, "psk": "secret", "udp": true,
	})
	want := `s=snell,e.com,6000,version=4,psk="secret",udp-relay=true`
	if got != want {
		t.Errorf("snell v4 mismatch:\n got: %s\nwant: %s", got, want)
	}

	// version 2 must NOT emit udp-relay
	got2 := surfboardProduce(t, Proxy{
		"name": "s", "type": "snell", "server": "e.com", "port": 6000,
		"version": 2, "psk": "secret", "udp": true,
	})
	if strings.Contains(got2, "udp-relay") {
		t.Errorf("snell v2 should not contain udp-relay, got: %s", got2)
	}
}

func TestSurfboardSnellInvalidVersion(t *testing.T) {
	err := surfboardProduceErr(t, Proxy{
		"name": "s", "type": "snell", "server": "e.com", "port": 6000,
		"version": 9,
	})
	if err == nil || !strings.Contains(err.Error(), "snell version") {
		t.Errorf("expected snell version rejection, got %v", err)
	}
}

func TestSurfboardSnellObfs(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "s", "type": "snell", "server": "e.com", "port": 6000,
		"version": 3, "psk": "secret",
		"obfs-opts": map[string]interface{}{
			"mode": "http", "host": "bing.com", "path": "/x",
		},
	})
	for _, want := range []string{",obfs=http", ",obfs-host=bing.com", ",obfs-uri=/x"} {
		if !strings.Contains(got, want) {
			t.Errorf("snell obfs missing %q in %s", want, got)
		}
	}
}

func TestSurfboardShadowsocks2022Cipher(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "ss", "type": "ss", "server": "e.com", "port": 8388,
		"cipher": "2022-blake3-aes-256-gcm", "password": "pw",
	})
	want := `ss=ss,e.com,8388,encrypt-method=2022-blake3-aes-256-gcm,password="pw"`
	if got != want {
		t.Errorf("ss 2022 cipher mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestSurfboardShadowsocksPasswordQuoted(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "ss", "type": "ss", "server": "e.com", "port": 8388,
		"cipher": "aes-128-gcm", "password": "p@ss",
	})
	if !strings.Contains(got, `password="p@ss"`) {
		t.Errorf("ss password should be quoted, got: %s", got)
	}
}

func TestSurfboardTrojanTlsAndBlockQuic(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "t", "type": "trojan", "server": "e.com", "port": 443,
		"password": "pw", "tls": true, "sni": "e.com",
		"tls-fingerprint": "ABCD", "skip-cert-verify": true,
		"udp": true, "block-quic": "off",
	})
	for _, want := range []string{
		"t=trojan,e.com,443", ",password=pw", ",tls=true",
		",server-cert-fingerprint-sha256=ABCD", `,sni="e.com"`,
		",skip-cert-verify=true", ",udp-relay=true", ",block-quic=off",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("trojan missing %q in %s", want, got)
		}
	}
	// trojan password must NOT be quoted
	if strings.Contains(got, `password="pw"`) {
		t.Errorf("trojan password should not be quoted, got: %s", got)
	}
}

func TestSurfboardVmessTlsGating(t *testing.T) {
	// tls=false => no sni / fingerprint emitted even if present
	got := surfboardProduce(t, Proxy{
		"name": "v", "type": "vmess", "server": "e.com", "port": 443,
		"uuid": "uuid-1", "alterId": 0, "tls": false,
		"sni": "e.com", "tls-fingerprint": "ABCD",
	})
	if strings.Contains(got, "sni=") || strings.Contains(got, "server-cert-fingerprint") {
		t.Errorf("vmess tls=false must not emit tls params, got: %s", got)
	}
	if !strings.Contains(got, ",vmess-aead=true") {
		t.Errorf("vmess alterId=0 should be aead=true, got: %s", got)
	}

	// tls=true => params emitted (sni quoted)
	got2 := surfboardProduce(t, Proxy{
		"name": "v", "type": "vmess", "server": "e.com", "port": 443,
		"uuid": "uuid-1", "alterId": 0, "tls": true,
		"sni": "e.com",
	})
	if !strings.Contains(got2, `,sni="e.com"`) {
		t.Errorf("vmess tls=true should emit quoted sni, got: %s", got2)
	}
}

func TestSurfboardVmessAeadFromAlterId(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "v", "type": "vmess", "server": "e.com", "port": 443,
		"uuid": "uuid-1", "alterId": 64,
	})
	if !strings.Contains(got, ",vmess-aead=false") {
		t.Errorf("vmess alterId=64 should be aead=false, got: %s", got)
	}
}

func TestSurfboardWsTransportHeaders(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "v", "type": "vmess", "server": "e.com", "port": 443,
		"uuid":    "uuid-1",
		"network": "ws",
		"ws-opts": map[string]interface{}{
			"path":    "/path",
			"headers": map[string]interface{}{"Host": "bing.com"},
		},
	})
	if !strings.Contains(got, ",ws=true") || !strings.Contains(got, ",ws-path=/path") {
		t.Errorf("ws transport missing in %s", got)
	}
	if !strings.Contains(got, `,ws-headers=Host:"bing.com"`) {
		t.Errorf("ws host header should be quoted, got: %s", got)
	}
}

func TestSurfboardTransportRejectsRealityAndNonTcp(t *testing.T) {
	err := surfboardProduceErr(t, Proxy{
		"name": "t", "type": "trojan", "server": "e.com", "port": 443,
		"password": "pw", "network": "tcp",
		"reality-opts": map[string]interface{}{"public-key": "k"},
	})
	if err == nil || !strings.Contains(err.Error(), "reality") {
		t.Errorf("expected reality rejection, got %v", err)
	}

	err2 := surfboardProduceErr(t, Proxy{
		"name": "t", "type": "trojan", "server": "e.com", "port": 443,
		"password": "pw", "network": "grpc",
	})
	if err2 == nil || !strings.Contains(err2.Error(), "unsupported") {
		t.Errorf("expected grpc network rejection, got %v", err2)
	}
}

func TestSurfboardHttpsType(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "h", "type": "http", "server": "e.com", "port": 8080,
		"tls": true, "username": "u", "password": "p",
		"skip-cert-verify": true,
	})
	if !strings.HasPrefix(got, "h=https,e.com,8080,u,p") {
		t.Errorf("http(s) prefix mismatch, got: %s", got)
	}
	if !strings.Contains(got, ",skip-cert-verify=true") {
		t.Errorf("http tls=true should emit skip-cert-verify, got: %s", got)
	}
}

func TestSurfboardWireguard(t *testing.T) {
	got := surfboardProduce(t, Proxy{
		"name": "wg", "type": "wireguard-surge", "section-name": "Sec",
		"block-quic": "on",
	})
	want := "wg=wireguard,section-name=Sec,block-quic=on"
	if got != want {
		t.Errorf("wireguard mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestSurfboardWsHttpUpgradeRejected(t *testing.T) {
	err := surfboardProduceErr(t, Proxy{
		"name": "v", "type": "vmess", "server": "e.com", "port": 443,
		"uuid": "u", "network": "ws",
		"ws-opts": map[string]interface{}{"v2ray-http-upgrade": true},
	})
	if err == nil || !strings.Contains(err.Error(), "http upgrade") {
		t.Errorf("expected http upgrade rejection, got %v", err)
	}
}
