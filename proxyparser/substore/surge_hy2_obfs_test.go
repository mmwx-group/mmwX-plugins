package substore

import (
	"strings"
	"testing"
)

// Surge 自 2026-06-22(上游 9405ac6f)起 salamander 与 gecko 两种混淆都收,
// 且各自用不同的字段名。此前我们只认 salamander,gecko 节点会被判成不支持。
func TestSurgeHysteria2SupportsGeckoAndSalamander(t *testing.T) {
	for _, tc := range []struct{ obfs, field string }{
		{"salamander", "salamander-password"},
		{"gecko", "gecko-password"},
	} {
		t.Run(tc.obfs, func(t *testing.T) {
			out, err := NewSurgeProducer().ProduceOne(Proxy{
				"name": "hy2", "type": "hysteria2", "server": "1.2.3.4", "port": 443,
				"password": "pw", "obfs": tc.obfs, "obfs-password": "obfspw",
			}, "", &ProduceOptions{IncludeUnsupportedProxy: true})
			if err != nil {
				t.Fatalf("%s 不该被拒: %v", tc.obfs, err)
			}
			if !strings.Contains(out, tc.field+`="obfspw"`) {
				t.Fatalf("输出里应带 %s,实际: %s", tc.field, out)
			}
		})
	}
}

// 认不出的混淆仍要报错。
func TestSurgeHysteria2RejectsUnknownObfs(t *testing.T) {
	_, err := NewSurgeProducer().ProduceOne(Proxy{
		"name": "hy2", "type": "hysteria2", "server": "1.2.3.4", "port": 443,
		"password": "pw", "obfs": "whatever", "obfs-password": "x",
	}, "", &ProduceOptions{IncludeUnsupportedProxy: true})
	if err == nil {
		t.Fatal("未知混淆应被拒")
	}
}

// Surfboard 自 2026-07-19(上游 2b28e1b5)起支持 TUIC v5。
// 此前没有这个分支,TUIC 节点会被当成「不支持的类型」直接丢出订阅。
func TestSurfboardTuicV5(t *testing.T) {
	out, err := (&SurfboardProducer{}).Produce([]Proxy{{
		"name": "tuic1", "type": "tuic", "server": "1.2.3.4", "port": 443,
		"uuid": "uuid-1", "password": "pw", "alpn": []interface{}{"h3"}, "udp": true,
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("TUIC v5 不该被拒: %v", err)
	}
	got, _ := out.(string)
	for _, want := range []string{"tuic1=tuic-v5,1.2.3.4,443", "uuid=uuid-1", `password="pw"`, `alpn="h3"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("输出缺 %q,实际: %s", want, got)
		}
	}
}

// 带 token 的是 TUIC v4,Surfboard 不认,要拒绝(Produce 里逐个跳过,不让整份订阅失败)。
func TestSurfboardTuicV4Rejected(t *testing.T) {
	v4 := Proxy{"name": "tuic-v4", "type": "tuic", "server": "1.2.3.4", "port": 443, "token": "tk"}
	if _, err := NewSurfboardProducer().produceSingle(v4); err == nil {
		t.Fatal("TUIC v4 应被拒")
	}
	out, err := (&SurfboardProducer{}).Produce([]Proxy{v4}, "", &ProduceOptions{})
	if err != nil || out != "" {
		t.Fatalf("TUIC v4 应被跳过,得到 %q / %v", out, err)
	}
}

// Surge 自 2026-07-18(上游 cfdcc035)起支持 server-cert-verify-name:
// 证书校验用的名字可以和 SNI 分开。节点字段是 name-cert-verify。
func TestSurgeServerCertVerifyName(t *testing.T) {
	out, err := NewSurgeProducer().ProduceOne(Proxy{
		"name": "t", "type": "trojan", "server": "1.2.3.4", "port": 443,
		"password": "pw", "sni": "a.example.com", "name-cert-verify": "b.example.com",
	}, "", &ProduceOptions{})
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if !strings.Contains(out, "server-cert-verify-name=b.example.com") {
		t.Fatalf("应输出 server-cert-verify-name,实际: %s", out)
	}
	if !strings.Contains(out, "sni=a.example.com") {
		t.Fatalf("sni 不该被顶掉,实际: %s", out)
	}
}
