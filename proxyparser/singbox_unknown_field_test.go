package proxyparser

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

// 带 headerType=none 的 vless 分享链接(xray 面板常见)转成 sing-box 后不能出现 headerType ——
// sing-box 1.15 遇到未知字段会拒绝加载整份配置(用户实报 outbounds[8].headerType: unknown field)。
func TestVlessHeaderTypeNotInSingboxOutput(t *testing.T) {
	node, err := Parse("vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&headerType=none&security=tls&sni=example.com#n1")
	if err != nil {
		t.Fatal(err)
	}
	if node["headerType"] != "none" {
		t.Fatalf("解析结果应带 headerType(本测试的前提),得到 %v", node["headerType"])
	}
	out, err := substore.NewSingboxProducer().Produce([]substore.Proxy{substore.Proxy(node)}, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "headerType") || strings.Contains(string(b), "header_type") {
		t.Fatalf("sing-box 输出里不应有 headerType: %s", b)
	}
}
