package proxyparser

import (
	"encoding/base64"
	"testing"
)

func TestPreprocess(t *testing.T) {
	uriList := "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#a\ntrojan://p@1.2.3.4:443#b"

	// 明文 URI 列表
	if k := DetectContentType([]byte(uriList)); k != ContentURIList {
		t.Errorf("明文 URI 列表 kind=%v, want ContentURIList", k)
	}
	ps, kind, _, err := Preprocess([]byte(uriList))
	if err != nil || kind != ContentURIList || len(ps) != 2 {
		t.Errorf("Preprocess 明文: kind=%v n=%d err=%v", kind, len(ps), err)
	}

	// base64 编码的 URI 列表
	b64 := base64.StdEncoding.EncodeToString([]byte(uriList))
	if k := DetectContentType([]byte(b64)); k != ContentURIList {
		t.Errorf("base64 URI 列表 kind=%v, want ContentURIList", k)
	}
	ps2, kind2, _, _ := Preprocess([]byte(b64))
	if kind2 != ContentURIList || len(ps2) != 2 {
		t.Errorf("Preprocess base64: kind=%v n=%d", kind2, len(ps2))
	}

	// Clash YAML
	if k := DetectContentType([]byte("proxies:\n  - name: a\n    type: ss")); k != ContentClashYAML {
		t.Errorf("YAML kind=%v, want ContentClashYAML", k)
	}

	// HTML
	if k := DetectContentType([]byte("<!DOCTYPE html><html><body>")); k != ContentHTML {
		t.Errorf("HTML kind=%v, want ContentHTML", k)
	}
}

func TestIsSupportedURI(t *testing.T) {
	yes := []string{"vless://x", "hysteria2://x", "naive+https://x", "ss://x"}
	no := []string{"random text", "proxies:", ""}
	for _, s := range yes {
		if !IsSupportedURI(s) {
			t.Errorf("IsSupportedURI(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if IsSupportedURI(s) {
			t.Errorf("IsSupportedURI(%q) = true, want false", s)
		}
	}
}
