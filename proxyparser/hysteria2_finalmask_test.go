package proxyparser

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

// 妙妙屋X #1672:Xray 的 hysteria2 分享链接带 fm=(finalmask:UDP 自定义包头 + quicParams),
// 以前解析时整段丢掉,导入后少了伪装头,服务端不认。
const hy2FinalmaskJSON = `{"udp":[{"type":"header-custom","settings":{"client":[{"type":"str","packet":"CDXUDP01"}],"server":[{"type":"str","packet":"CDXUDP01"}]}}],"quicParams":{"congestion":"bbr","disablePathMTUDiscovery":true,"disableGSO":true,"keepAlivePeriod":10}}`

func TestHysteria2FinalmaskRoundTrip(t *testing.T) {
	uri := "hysteria2://pass@192.0.2.1:1305?sni=hy2.local&insecure=1&fm=" + url.QueryEscape(hy2FinalmaskJSON) + "#jp"
	node, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	fm, ok := node["_finalmask"].(map[string]any)
	if !ok {
		t.Fatalf("_finalmask 应是对象: %#v", node["_finalmask"])
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(hy2FinalmaskJSON), &want)
	gotB, _ := json.Marshal(fm)
	wantB, _ := json.Marshal(want)
	if string(gotB) != string(wantB) {
		t.Fatalf("_finalmask 内容不对:\n got %s\nwant %s", gotB, wantB)
	}
	if node["password"] != "pass" || node["sni"] != "hy2.local" || node["skip-cert-verify"] != true {
		t.Fatalf("其它字段不该受影响: %#v", node)
	}

	// 写回分享链接:fm 原样带回,再解析一遍内容不变
	out, err := substore.NewURIProducer().Produce([]substore.Proxy{substore.Proxy(node)}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	link := strings.TrimSpace(out.(string))
	if !strings.Contains(link, "&fm=") {
		t.Fatalf("hy2 链接应带 fm=: %s", link)
	}
	again, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	againB, _ := json.Marshal(again["_finalmask"])
	if string(againB) != string(wantB) {
		t.Fatalf("往返后 finalmask 变了:\n got %s\nwant %s", againB, wantB)
	}

	// Clash/mihomo 不认识 finalmask:输出里不能出现
	cm, err := substore.NewClashMetaProducer().Produce([]substore.Proxy{substore.Proxy(node)}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(cm); strings.Contains(string(b), "finalmask") {
		t.Fatalf("clash meta 输出不该带 finalmask: %s", b)
	}
}

// fm 不是合法 JSON 对象时原样存字符串,写回时也原样带回。
func TestHysteria2FinalmaskRawString(t *testing.T) {
	node, err := Parse("hysteria2://pass@192.0.2.1:443?fm=" + url.QueryEscape("not-json") + "#x")
	if err != nil {
		t.Fatal(err)
	}
	if node["_finalmask"] != "not-json" {
		t.Fatalf("非 JSON 应原样存: %#v", node["_finalmask"])
	}
	// 不带 fm 的不该多出字段
	plain, _ := Parse("hysteria2://pass@192.0.2.1:443#x")
	if _, ok := plain["_finalmask"]; ok {
		t.Fatalf("没有 fm 不应有 _finalmask: %#v", plain)
	}
}
