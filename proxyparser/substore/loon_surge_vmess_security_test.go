package substore

import (
	"strings"
	"testing"
)

// Loon 用 ietf 拼法。从前这里把 cipher 原样透出 —— clash 配置里合法的
// chacha20-poly1305 到了 Loon 就不认,与 QX 那处是同一次移植漏的同类问题。
func TestLoonFormatVmessSecurity(t *testing.T) {
	cases := []struct{ in, want string }{
		{"chacha20-poly1305", "chacha20-ietf-poly1305"},
		{"chacha20-ietf-poly1305", "chacha20-ietf-poly1305"},
		{"aes-128-gcm", "aes-128-gcm"},
		{"none", "none"},
		{"auto", "auto"},
		{"", "auto"},
		{"zero", "auto"}, // 白名单外回落
	}
	for _, c := range cases {
		if got := loonFormatVmessSecurity(c.in); got != c.want {
			t.Fatalf("loonFormatVmessSecurity(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// Surge 的 encrypt-method 从前整个漏掉了。空串表示不输出这个字段。
func TestSurgeFormatVmessEncryptMethod(t *testing.T) {
	cases := []struct{ in, want string }{
		{"aes-128-gcm", "aes-128-gcm"},
		{"chacha20-poly1305", "chacha20-ietf-poly1305"},
		{"chacha20-ietf-poly1305", "chacha20-ietf-poly1305"},
		// auto / 空 / 白名单外:不输出,交给 Surge 自己挑
		{"auto", ""},
		{"", ""},
		{"none", ""},
		{"zero", ""},
	}
	for _, c := range cases {
		if got := surgeFormatVmessEncryptMethod(c.in); got != c.want {
			t.Fatalf("surgeFormatVmessEncryptMethod(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// 整行产出:Surge 的 aes-128-gcm 要真的写进去(从前完全没有这个字段)。
func TestSurgeVmessLineHasEncryptMethod(t *testing.T) {
	p := NewSurgeProducer()
	out, err := p.Produce([]Proxy{{
		"name": "n", "type": "vmess", "server": "1.1.1.1", "port": 443,
		"uuid": "11111111-1111-1111-1111-111111111111", "cipher": "aes-128-gcm",
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("产出失败: %v", err)
	}
	line, _ := out.(string)
	if !strings.Contains(line, "encrypt-method=aes-128-gcm") {
		t.Fatalf("缺少 encrypt-method: %s", line)
	}
	// auto 不该写这个字段
	out2, _ := p.Produce([]Proxy{{
		"name": "n2", "type": "vmess", "server": "1.1.1.2", "port": 443,
		"uuid": "22222222-2222-2222-2222-222222222222", "cipher": "auto",
	}}, "", &ProduceOptions{})
	if line2, _ := out2.(string); strings.Contains(line2, "encrypt-method") {
		t.Fatalf("auto 不该输出 encrypt-method: %s", line2)
	}
}
