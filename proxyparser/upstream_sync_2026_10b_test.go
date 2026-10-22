package proxyparser

import "testing"

// 2026-10 第二轮跟上游 Sub-Store 同步(补 09-04 以来漏掉的几项 + a3e61061 之后)的解析行为。

// SS 链接:udp=0 / false / off 关 UDP,其余(含不写)都开(上游 7b9d8227)
func TestParseShadowsocksUDPFlag(t *testing.T) {
	const base = "ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example.com:8388"
	cases := map[string]bool{
		base + "#a":           true,
		base + "?udp=1#a":     true,
		base + "?udp=0#a":     false,
		base + "?udp=false#a": false,
		base + "?udp=OFF#a":   false,
	}
	for uri, want := range cases {
		node, err := Parse(uri)
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if got, _ := node["udp"].(bool); got != want {
			t.Fatalf("%s: udp=%v,应为 %v", uri, node["udp"], want)
		}
	}
}

// VLESS 风格的 vmess://uuid@host:port?...(上游 5d7126e9)
func TestParseVmessQueryStyle(t *testing.T) {
	node, err := Parse("vmess://9a6d0d6e-3f1c-4a4b-9a52-1d2b3c4d5e6f@v.example.com:443?security=reality&pbk=PUBKEY&sid=ab&encryption=chacha20-ietf-poly1305&flow=xtls-rprx-vision&fp=chrome#VM%20R")
	if err != nil {
		t.Fatal(err)
	}
	if node["type"] != "vmess" || node["cipher"] != "chacha20-poly1305" || node["alterId"] != 0 {
		t.Fatalf("应解析成 VMess: %v", node)
	}
	if _, ok := node["flow"]; ok {
		t.Fatalf("VMess 不带 flow: %v", node["flow"])
	}
	if _, ok := node["encryption"]; ok {
		t.Fatalf("encryption 应转成 cipher: %v", node)
	}
	ro, _ := node["reality-opts"].(map[string]any)
	if ro["public-key"] != "PUBKEY" || node["name"] != "VM R" {
		t.Fatalf("REALITY / 名称不对: %v", node)
	}
	// 老的 base64 JSON 写法照旧
	if n, err := Parse("vmess://eyJ2IjoiMiIsInBzIjoiYSIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1IiwiYWlkIjoiMCIsIm5ldCI6InRjcCJ9"); err != nil || n["server"] != "1.2.3.4" {
		t.Fatalf("base64 写法应照旧: %v %v", n, err)
	}
}

// VLESS 链接的 fm=(finalmask,上游 18dfe4c0)
func TestParseVlessFinalmask(t *testing.T) {
	node, err := Parse(`vless://u@a.com:443?security=tls&fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22salamander%22%7D%5D%7D#x`)
	if err != nil {
		t.Fatal(err)
	}
	fm, ok := node["_finalmask"].(map[string]any)
	if !ok || fm["udp"] == nil {
		t.Fatalf("JSON 对象应存成对象: %#v", node["_finalmask"])
	}
	node, _ = Parse(`vless://u@a.com:443?security=tls&fm=raw-text#x`)
	if node["_finalmask"] != "raw-text" {
		t.Fatalf("不是 JSON 时原样存字符串: %#v", node["_finalmask"])
	}
}
