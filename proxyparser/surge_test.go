package proxyparser

import (
	"testing"
)

func TestParseSurgeLineSnell(t *testing.T) {
	node := parseSurgeLine("香港中转 = snell, 1.2.3.4, 6000, psk=mypsk, version=4, obfs=http, obfs-host=bing.com, tfo=true, udp-relay=true, reuse=true")
	if node == nil {
		t.Fatal("snell 行解析返回 nil")
	}
	checks := map[string]any{
		"name": "香港中转", "type": "snell", "server": "1.2.3.4", "port": 6000,
		"psk": "mypsk", "version": 4, "tfo": true, "udp": true, "reuse": true,
	}
	for k, want := range checks {
		if node[k] != want {
			t.Errorf("node[%q] = %v, want %v", k, node[k], want)
		}
	}
	obfs, ok := node["obfs-opts"].(map[string]any)
	if !ok {
		t.Fatalf("obfs-opts 类型错误: %T", node["obfs-opts"])
	}
	if obfs["mode"] != "http" || obfs["host"] != "bing.com" {
		t.Errorf("obfs-opts = %v", obfs)
	}
}

func TestParseSurgeLineSnellDefaults(t *testing.T) {
	// version 缺省为 4;obfs=none 不写 obfs-opts;开关默认不写
	node := parseSurgeLine("s = snell, h.example.com, 443, psk=k, obfs=none")
	if node == nil {
		t.Fatal("返回 nil")
	}
	if node["version"] != 4 {
		t.Errorf("version 默认值 = %v, want 4", node["version"])
	}
	if _, present := node["obfs-opts"]; present {
		t.Error("obfs=none 不应产生 obfs-opts")
	}
	for _, k := range []string{"tfo", "udp", "reuse"} {
		if _, present := node[k]; present {
			t.Errorf("默认不应出现 %q", k)
		}
	}
}

func TestParseSurgeLineNonSnellAndInvalid(t *testing.T) {
	// 非 snell 类型:保持历史行为返回 nil
	if node := parseSurgeLine("x = vmess, h.com, 443, username=uuid"); node != nil {
		t.Errorf("非 snell 应返回 nil, got %v", node)
	}
	// 字段不足
	if node := parseSurgeLine("x = snell, h.com"); node != nil {
		t.Errorf("字段不足应返回 nil, got %v", node)
	}
	// 无等号
	if node := parseSurgeLine("just a plain line"); node != nil {
		t.Errorf("无等号应返回 nil, got %v", node)
	}
}

func TestParseSubscriptionMixedURIAndSurge(t *testing.T) {
	content := "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss-node\ns = snell, h.example.com, 443, psk=k"
	proxies, err := ParseSubscription(content)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("应解析出 2 个节点 (1 URI + 1 surge snell), got %d: %v", len(proxies), proxies)
	}
	var hasSnell bool
	for _, p := range proxies {
		if p["type"] == "snell" && p["server"] == "h.example.com" {
			hasSnell = true
		}
	}
	if !hasSnell {
		t.Errorf("混合内容里缺少 surge snell 节点: %v", proxies)
	}
}
