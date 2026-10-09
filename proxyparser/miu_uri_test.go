package proxyparser

import (
	"reflect"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

// miu:// 是妙妙屋自有协议的分享链接,形态同 anytls://,凭据字段是 psk。
// psk 是 base64(带 + / =):认证用的是字符串本身的 sha256,解析与导出都不能改动它一个字节。

const miuTestPSK = "c2VjcmV0+XNlY3JldC1zZWN/ZXQtc2VjcmV0LTEyMzQ="

func TestParseMiuURLReality(t *testing.T) {
	uri := "miu://c2VjcmV0+XNlY3JldC1zZWN%2FZXQtc2VjcmV0LTEyMzQ=@us-a.example.com:38294/?" +
		"sni=www.example.com&fp=chrome&security=reality&pbk=0WxD-SzAKKrjqiubZJ3o&sid=e1f7bbf1&udp=1#%E7%BE%8E%E5%9B%BD%20Miu"
	node, err := Parse(uri)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	subset(t, "miu+reality", node, map[string]any{
		"type":               "miu",
		"server":             "us-a.example.com",
		"port":               38294,
		"psk":                miuTestPSK,
		"name":               "美国 Miu",
		"sni":                "www.example.com",
		"client-fingerprint": "chrome",
		"udp":                true,
		"reality-opts": map[string]any{
			"public-key": "0WxD-SzAKKrjqiubZJ3o",
			"short-id":   "e1f7bbf1",
		},
	})
	// 自有协议不带 anytls 那种给第三方客户端看的 network / security 标记
	for _, k := range []string{"network", "security", "password"} {
		if _, ok := node[k]; ok {
			t.Errorf("miu 节点不应带 %s, got=%v", k, node[k])
		}
	}
}

func TestParseMiuURLTLS(t *testing.T) {
	node, err := Parse("miu://" + "raw-psk-at-least-16-bytes" + "@1.2.3.4:443?sni=a.example.com&insecure=1&alpn=h2,http/1.1&udp=0#n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	subset(t, "miu+tls", node, map[string]any{
		"type":             "miu",
		"server":           "1.2.3.4",
		"port":             443,
		"psk":              "raw-psk-at-least-16-bytes",
		"sni":              "a.example.com",
		"skip-cert-verify": true,
		"udp":              false,
	})
	if got := node["alpn"]; !reflect.DeepEqual(got, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn = %#v", got)
	}
	if _, ok := node["reality-opts"]; ok {
		t.Error("没写 security=reality 不该有 reality-opts")
	}
	if _, err := Parse("miu://no-at-sign:443"); err == nil {
		t.Error("缺 @ 的链接应当报错")
	}
}

// 导出再解析,字段原样回来(REALITY 与 TLS 两种)。
func TestMiuURIRoundTrip(t *testing.T) {
	for _, proxy := range []substore.Proxy{
		{
			"name": "美国 Akko #1", "type": "miu", "server": "us-a.example.com", "port": 38294,
			"psk": miuTestPSK, "udp": true, "sni": "www.example.com", "client-fingerprint": "chrome",
			"reality-opts": map[string]any{"public-key": "0WxD-SzAKKrjqiubZJ3o", "short-id": "e1f7bbf1"},
			"vision":       true, // 第一版的字段:不导出
		},
		{
			"name": "tls", "type": "miu", "server": "2001:db8::1", "port": 443,
			"psk": "raw-psk-at-least-16-bytes", "udp": false, "sni": "a.example.com",
			"skip-cert-verify": true, "alpn": []string{"h2", "http/1.1"},
		},
	} {
		uri, err := substore.NewURIProducer().ProduceOne(proxy)
		if err != nil {
			t.Fatalf("%v: 导出失败: %v", proxy["name"], err)
		}
		back, err := Parse(uri)
		if err != nil {
			t.Fatalf("%v: 解析 %q 失败: %v", proxy["name"], uri, err)
		}
		for _, k := range []string{"name", "type", "server", "port", "psk", "udp", "sni"} {
			if !reflect.DeepEqual(back[k], proxy[k]) {
				t.Errorf("%v: %s = %#v, want %#v (uri %s)", proxy["name"], k, back[k], proxy[k], uri)
			}
		}
		if ro, ok := proxy["reality-opts"]; ok && !reflect.DeepEqual(back["reality-opts"], ro) {
			t.Errorf("%v: reality-opts = %#v", proxy["name"], back["reality-opts"])
		}
		if _, ok := back["vision"]; ok {
			t.Errorf("%v: vision 不该出现在链接里", proxy["name"])
		}
	}
}
