package substore

import (
	"strings"
	"testing"
)

// 自签证书的 anytls 节点复制成 URI 要带上证书指纹 pcs(许可证站 #1920),
// 没指纹时不能凭空多出 pcs。
func TestURIAnyTLSCertFingerprint(t *testing.T) {
	const fp = "3f5c0e8a9b1d2c4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"
	uri := produceURI(t, Proxy{
		"type":             "anytls",
		"name":             "at",
		"server":           "a.example.com",
		"port":             443,
		"password":         "pw",
		"sni":              "a.example.com",
		"skip-cert-verify": false,
		"tls-fingerprint":  fp,
	})
	mustContain(t, uri, "pcs="+fp)

	plain := produceURI(t, Proxy{
		"type":     "anytls",
		"name":     "at2",
		"server":   "a.example.com",
		"port":     443,
		"password": "pw",
	})
	if strings.Contains(plain, "pcs=") {
		t.Fatalf("没有指纹的节点不应输出 pcs: %s", plain)
	}
}
