package substore

import (
	"strings"
	"testing"
)

// Quantumult X 的 vmess method 只认 none / chacha20-poly1305。
// 从前这里把 cipher 原样透出、auto 和空串换成 chacha20-ietf-poly1305 ——
// 那个值 QX 不认,于是 clash 侧最常见的两种配置(auto、aes-128-gcm)产出的
// server_local 行全是坏的,QX 解析不了节点 = 用户说的「QX 模板不可用」。
func TestQXFormatVmessMethod(t *testing.T) {
	cases := []struct{ in, want string }{
		{"chacha20-ietf-poly1305", "chacha20-poly1305"},
		{"CHACHA20-IETF-POLY1305", "chacha20-poly1305"},
		{" chacha20-ietf-poly1305 ", "chacha20-poly1305"},
		{"chacha20-poly1305", "chacha20-poly1305"},
		{"none", "none"},
		// QX 不支持的一律回落 —— VMess 的 security 由客户端决定,
		// 服务端按包头自适应,换加密方式不需要服务端配合
		{"auto", "chacha20-poly1305"},
		{"", "chacha20-poly1305"},
		{"aes-128-gcm", "chacha20-poly1305"},
		{"zero", "chacha20-poly1305"},
	}
	for _, c := range cases {
		if got := qxFormatVmessMethod(c.in); got != c.want {
			t.Fatalf("qxFormatVmessMethod(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// 整行产出里不能再出现 QX 不认的 method。
func TestQXVmessLineUsesSupportedMethod(t *testing.T) {
	p := NewQXProducer()
	for _, cipher := range []string{"auto", "aes-128-gcm", "chacha20-ietf-poly1305", ""} {
		out, err := p.Produce([]Proxy{{
			"name": "n", "type": "vmess", "server": "1.1.1.1", "port": 443,
			"uuid": "11111111-1111-1111-1111-111111111111", "cipher": cipher,
		}}, "", &ProduceOptions{})
		if err != nil {
			t.Fatalf("cipher=%q 产出失败: %v", cipher, err)
		}
		line, _ := out.(string)
		if line == "" {
			t.Fatalf("cipher=%q 被丢弃了", cipher)
		}
		if !strings.Contains(line, "method=chacha20-poly1305") &&
			!strings.Contains(line, "method=none") {
			t.Fatalf("cipher=%q 产出了 QX 不认的 method: %s", cipher, line)
		}
		if strings.Contains(line, "chacha20-ietf-poly1305") {
			t.Fatalf("cipher=%q 仍在输出 clash 写法: %s", cipher, line)
		}
	}
}
