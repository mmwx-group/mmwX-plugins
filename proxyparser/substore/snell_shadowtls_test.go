package substore

import (
	"encoding/json"
	"strings"
	"testing"
)

// 妙妙屋X 生成的 Snell + ShadowTLS 节点是 mihomo 写法(obfs-opts.mode = shadow-tls)。
func mmwxSnellShadowTLS() Proxy {
	return Proxy{
		"name": "snell-stls", "type": "snell", "server": "1.2.3.4", "port": 8443,
		"psk": "psk-x", "version": 5, "udp": true, "reuse": true,
		"obfs-opts": map[string]interface{}{"mode": "shadow-tls", "host": "www.apple.com", "password": "stls-pw", "version": 3},
	}
}

func TestSurgeSnellShadowTLS(t *testing.T) {
	out, err := (&SurgeProducer{}).snell(mmwxSnellShadowTLS())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shadow-tls-password=stls-pw", "shadow-tls-sni=www.apple.com", "shadow-tls-version=3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺 %s: %s", want, out)
		}
	}
	if strings.Contains(out, "obfs=") {
		t.Fatalf("不该写成 obfs=: %s", out)
	}
}

func TestSingboxSnellShadowTLS(t *testing.T) {
	res, err := NewSingboxProducer().Produce([]Proxy{mmwxSnellShadowTLS()}, "", &ProduceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	str, ok := res.(string)
	if !ok {
		t.Fatalf("sing-box 输出应为 JSON 字符串: %T", res)
	}
	b := []byte(str)
	var parsed struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("解析输出: %v %s", err, b)
	}
	var snell, st map[string]interface{}
	for _, o := range parsed.Outbounds {
		switch o["type"] {
		case "snell":
			snell = o
		case "shadowtls":
			st = o
		}
	}
	if snell == nil || st == nil {
		t.Fatalf("应输出 snell + shadowtls 两个出站: %s", b)
	}
	if snell["detour"] != "snell-stls_shadowtls" || st["tag"] != "snell-stls_shadowtls" {
		t.Fatalf("detour 对不上: %s", b)
	}
	if _, ok := snell["server"]; ok {
		t.Fatalf("经 detour 的 snell 不该带 server: %s", b)
	}
	if _, ok := snell["obfs_mode"]; ok {
		t.Fatalf("不该带 obfs_mode: %s", b)
	}
	tls, _ := st["tls"].(map[string]interface{})
	if st["password"] != "stls-pw" || st["server"] != "1.2.3.4" || tls["server_name"] != "www.apple.com" {
		t.Fatalf("shadowtls 出站字段不对: %s", b)
	}
	if v, _ := st["version"].(float64); v != 3 {
		t.Fatalf("version 应为 3: %s", b)
	}
}

func TestSnellShadowTLSUnsupportedFiltered(t *testing.T) {
	if _, err := (&SurfboardProducer{}).snell(mmwxSnellShadowTLS()); err == nil {
		t.Fatal("Surfboard 不支持 Snell + ShadowTLS,应报错跳过")
	}
	if !egernHasShadowTls(mmwxSnellShadowTLS()) {
		t.Fatal("Egern 应认出 obfs-opts 写法的 shadow-tls 并跳过")
	}
	// 原节点不能被改写(producer 拿的是共享的 map)
	p := mmwxSnellShadowTLS()
	_ = snellShadowTLSAsPlugin(p)
	if _, ok := p["obfs-opts"]; !ok || p["plugin"] != nil {
		t.Fatal("snellShadowTLSAsPlugin 不应改动原节点")
	}
}
