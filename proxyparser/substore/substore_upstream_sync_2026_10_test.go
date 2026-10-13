package substore

import (
	"strings"
	"testing"
)

// 2026-10 这一轮跟上游(Sub-Store a3e61061)同步的行为。

// Shadowrocket 支持 Snell v1–v6。模板版以前把 v4 以上整个丢掉,绑了模板的订阅里这些节点全部消失。
func TestShadowrocketTemplateKeepsSnellV4ToV6(t *testing.T) {
	p := NewShadowrocketTemplateProducer()
	for _, version := range []int{3, 4, 5, 6} {
		got := p.transformProxies([]Proxy{{
			"name": "s", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": version,
		}}, &ProduceOptions{})
		if len(got) != 1 {
			t.Fatalf("snell v%d 应保留,实际剩 %d 个", version, len(got))
		}
	}
	if got := p.transformProxies([]Proxy{{
		"name": "s", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 7,
	}}, &ProduceOptions{}); len(got) != 0 {
		t.Fatalf("snell v7 应过滤")
	}
}

// Snell 的 shadow-tls 插件写成 Shadowrocket 认的 obfs-opts;与原有 obfs 同时出现时没法表达,过滤。
func TestShadowrocketSnellShadowTLS(t *testing.T) {
	got, ok := srInternal(t, Proxy{
		"name": "s", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 5,
		"plugin":      "shadow-tls",
		"plugin-opts": map[string]interface{}{"host": "example.com", "password": "pw", "version": 3},
	})
	if !ok {
		t.Fatal("snell + shadow-tls 不应被过滤")
	}
	obfs := GetMap(got, "obfs-opts")
	if obfs == nil || GetString(obfs, "mode") != "shadow-tls" || GetString(obfs, "host") != "example.com" || GetString(obfs, "password") != "pw" {
		t.Fatalf("obfs-opts 不对: %v", got["obfs-opts"])
	}
	if IsPresent(got, "plugin") || IsPresent(got, "plugin-opts") {
		t.Fatalf("plugin / plugin-opts 应删掉: %v", got)
	}
	if _, ok := srInternal(t, Proxy{
		"name": "s", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 5,
		"plugin":      "shadow-tls",
		"plugin-opts": map[string]interface{}{"host": "example.com", "password": "pw", "version": 3},
		"obfs-opts":   map[string]interface{}{"mode": "http", "host": "bing.com"},
	}); ok {
		t.Fatal("shadow-tls 与 obfs 同时出现应过滤")
	}
}

func TestShadowrocketFiltersMasqueSurgeAndEasyTier(t *testing.T) {
	for _, typ := range []string{"masque-surge", "easytier"} {
		if _, ok := srInternal(t, Proxy{"name": "x", "type": typ, "server": "a.com", "port": 443}); ok {
			t.Errorf("%s 应过滤", typ)
		}
	}
}

// mihomo 不认 Surge 的 MASQUE 写法(上游 bcfdd10e)。
func TestClashMetaFiltersMasqueSurge(t *testing.T) {
	out, err := NewClashMetaProducer().Produce([]Proxy{
		{"name": "mq", "type": "masque-surge", "server": "a.com", "port": 443, "username": "u", "password": "p"},
		{"name": "ok", "type": "trojan", "server": "a.com", "port": 443, "password": "p"},
	}, "internal", &ProduceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := out.([]Proxy)
	if len(list) != 1 || GetString(list[0], "name") != "ok" {
		t.Fatalf("masque-surge 应过滤,实际: %v", out)
	}
}

// Loon 的 server-dns(上游 8c2a6956):所有协议通用,接在行尾。
func TestLoonServerDNS(t *testing.T) {
	out, err := NewLoonProducer().ProduceOne(Proxy{
		"name": "t", "type": "trojan", "server": "example.com", "port": 443, "password": "pw",
		"server-dns": []interface{}{"223.5.5.5", "https://dns.alidns.com/dns-query"},
	}, "", &ProduceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, `,server-dns="223.5.5.5,https://dns.alidns.com/dns-query"`) {
		t.Fatalf("行尾应带 server-dns,实际: %s", out)
	}
	plain, _ := NewLoonProducer().ProduceOne(Proxy{
		"name": "t", "type": "trojan", "server": "example.com", "port": 443, "password": "pw",
	}, "", &ProduceOptions{})
	if strings.Contains(plain, "server-dns") {
		t.Fatalf("没配时不该出现 server-dns: %s", plain)
	}
}

// Egern 的 ip_version(上游 ece585cd)。
func TestEgernIPVersion(t *testing.T) {
	out, err := (&EgernProducer{}).Produce([]Proxy{{
		"name": "t", "type": "trojan", "server": "example.com", "port": 443, "password": "pw",
		"ip-version": "ipv4-prefer",
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := out.(string); !strings.Contains(got, "v4_prefer") {
		t.Fatalf("应输出 ip_version: v4_prefer,实际: %s", got)
	}
}

// Surge:udp-relay 只留给 Shadowsocks / SOCKS5(上游 4a1e069c)。
func TestSurgeUDPRelayOnlyForShadowsocksAndSocks5(t *testing.T) {
	produce := func(proxy Proxy) string {
		out, err := NewSurgeProducer().ProduceOne(proxy, "", &ProduceOptions{})
		if err != nil {
			t.Fatalf("%v: %v", proxy["type"], err)
		}
		return out
	}
	keep := []Proxy{
		{"name": "ss", "type": "ss", "server": "a.com", "port": 8388, "cipher": "aes-128-gcm", "password": "pw", "udp": true},
		{"name": "s5", "type": "socks5", "server": "a.com", "port": 1080, "udp": true},
	}
	for _, proxy := range keep {
		if out := produce(proxy); !strings.Contains(out, "udp-relay=true") {
			t.Errorf("%v 应带 udp-relay: %s", proxy["type"], out)
		}
	}
	drop := []Proxy{
		{"name": "tj", "type": "trojan", "server": "a.com", "port": 443, "password": "pw", "udp": true},
		{"name": "vm", "type": "vmess", "server": "a.com", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "cipher": "auto", "udp": true},
		{"name": "at", "type": "anytls", "server": "a.com", "port": 443, "password": "pw", "udp": true},
		{"name": "sn", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 5, "udp": true},
		{"name": "tu", "type": "tuic", "server": "a.com", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "password": "pw", "udp": true},
		{"name": "h2", "type": "hysteria2", "server": "a.com", "port": 443, "password": "pw", "udp": true},
	}
	for _, proxy := range drop {
		if out := produce(proxy); strings.Contains(out, "udp-relay=") {
			t.Errorf("%v 不应带 udp-relay: %s", proxy["type"], out)
		}
	}
}

// sing-box 的 SSH 私钥:内容走 private_key,路径走 private_key_path(上游 04f44c2a)。
func TestSingboxSSHPrivateKeyInlineOrPath(t *testing.T) {
	p := NewSingboxProducer()
	inline, err := p.sshParser(Proxy{"name": "s", "type": "ssh", "server": "a.com", "port": 22, "username": "u",
		"private-key": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"})
	if err != nil {
		t.Fatal(err)
	}
	if inline["private_key"] == nil || inline["private_key_path"] != nil {
		t.Fatalf("私钥内容应写进 private_key: %v", inline)
	}
	path, err := p.sshParser(Proxy{"name": "s", "type": "ssh", "server": "a.com", "port": 22, "username": "u", "private-key": "/root/.ssh/id_ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if path["private_key_path"] != "/root/.ssh/id_ed25519" || path["private_key"] != nil {
		t.Fatalf("路径应写进 private_key_path: %v", path)
	}
}

// VLESS 链接带出 / 读回 reality 的 support-x25519mlkem768(上游 5d7126e9)。
func TestVLESSURIRealityMLKEM(t *testing.T) {
	out, err := NewURIProducer().ProduceOne(Proxy{
		"name": "v", "type": "vless", "server": "a.com", "port": 443, "uuid": "11111111-1111-1111-1111-111111111111",
		"tls": true, "servername": "www.example.com", "network": "tcp",
		"reality-opts": map[string]interface{}{"public-key": "PUBKEY", "short-id": "ab", "support-x25519mlkem768": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "support-x25519mlkem768=true") {
		t.Fatalf("链接里应带 support-x25519mlkem768: %s", out)
	}
}
