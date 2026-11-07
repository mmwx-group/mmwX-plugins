package proxyparser

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

func xhttpJSON(v any) string {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	b, _ = json.Marshal(out)
	return string(b)
}

// v2rayN / Xray 写法的 vless:// 链接(extra 里范围值数字、字符串都有)→ mihomo 的 xhttp-opts。
func TestParseVlessXHTTPExtra(t *testing.T) {
	extra := `{"headers":{"X-Token":"abc def","Host":"ignored"},"noGRPCHeader":true,"xPaddingBytes":"200-800",` +
		`"scMaxEachPostBytes":2000000,"xPaddingObfsMode":true,"xPaddingPlacement":"header",` +
		`"xmux":{"maxConnections":3,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":30},` +
		`"downloadSettings":{"address":"203.0.113.10","port":8443,"network":"xhttp","security":"tls",` +
		`"tlsSettings":{"serverName":"x.example.com","alpn":["h2"],"fingerprint":"chrome","pinnedPeerCertSha256":"AB:CD"},` +
		`"xhttpSettings":{"path":"/down","host":"cdn.example.com","headers":{"X-D":"1"},"extra":{"xmux":{"maxConcurrency":"16-32"}}}}}`
	link := "vless://u-1@x.example.com:8443?type=xhttp&security=tls&sni=x.example.com&path=%2Fxhttp&host=cdn.example.com&mode=packet-up&extra=" +
		url.QueryEscape(extra) + "#n"
	node, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if node["mode"] != "packet-up" {
		t.Errorf("顶层 mode 照旧: %v", node["mode"])
	}
	want := map[string]any{
		"path": "/xhttp", "host": "cdn.example.com", "mode": "packet-up",
		"headers":                map[string]any{"Host": "cdn.example.com", "X-Token": "abc def"},
		"no-grpc-header":         true,
		"x-padding-bytes":        "200-800",
		"x-padding-obfs-mode":    true,
		"x-padding-placement":    "header",
		"sc-max-each-post-bytes": "2000000",
		"reuse-settings": map[string]any{
			"max-connections": "3", "h-max-request-times": "600-900", "h-max-reusable-secs": "1800-3000", "h-keep-alive-period": 30,
		},
		"download-settings": map[string]any{
			"server": "203.0.113.10", "port": 8443, "tls": true,
			"servername": "x.example.com", "alpn": []string{"h2"}, "client-fingerprint": "chrome", "fingerprint": "AB:CD",
			"path": "/down", "host": "cdn.example.com", "headers": map[string]any{"X-D": "1"},
			"reuse-settings": map[string]any{"max-concurrency": "16-32"},
		},
	}
	if got := xhttpJSON(node["xhttp-opts"]); got != xhttpJSON(want) {
		t.Errorf("xhttp-opts 不对:\n got %s\nwant %s", got, xhttpJSON(want))
	}
}

// 下行是 REALITY;没写 security 的 downloadSettings 按 Xray 语义是不加密。
func TestParseVlessXHTTPExtraDownloadSecurity(t *testing.T) {
	extra := `{"downloadSettings":{"address":"dl.example.com","port":443,"security":"reality",` +
		`"realitySettings":{"serverName":"www.apple.com","fingerprint":"chrome","publicKey":"PBK","shortId":"ab"}}}`
	node, err := Parse("vless://u@x.example.com:443?type=xhttp&security=reality&pbk=PBK&sni=www.apple.com&extra=" + url.QueryEscape(extra))
	if err != nil {
		t.Fatal(err)
	}
	ds := node["xhttp-opts"].(map[string]any)["download-settings"]
	want := map[string]any{"server": "dl.example.com", "port": 443, "tls": true, "servername": "www.apple.com",
		"client-fingerprint": "chrome", "reality-opts": map[string]any{"public-key": "PBK", "short-id": "ab"}}
	if xhttpJSON(ds) != xhttpJSON(want) {
		t.Errorf("download-settings 不对:\n got %s\nwant %s", xhttpJSON(ds), xhttpJSON(want))
	}

	node, _ = Parse("vless://u@x.example.com:443?type=xhttp&security=tls&extra=" + url.QueryEscape(`{"downloadSettings":{"address":"1.2.3.4"}}`))
	ds = node["xhttp-opts"].(map[string]any)["download-settings"]
	if xhttpJSON(ds) != xhttpJSON(map[string]any{"server": "1.2.3.4", "tls": false}) {
		t.Errorf("没写 security 应是不加密: %s", xhttpJSON(ds))
	}

	// extra 不是 JSON:忽略,其它照旧
	node, err = Parse("vless://u@x.example.com:443?type=xhttp&path=%2Fp&extra=oops")
	if err != nil || node["xhttp-opts"].(map[string]any)["path"] != "/p" {
		t.Errorf("坏 extra 不该影响解析: %v %v", err, node)
	}
}

// 没有 extra 的旧链接:xhttp-opts 只多了 host / mode(mihomo 只认这两处),其余照旧。
func TestParseVlessXHTTPNoExtra(t *testing.T) {
	node, err := Parse("vless://u@x.example.com:443?type=xhttp&security=tls&path=%2Fp&host=h.example.com&mode=stream-up")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"path": "/p", "host": "h.example.com", "mode": "stream-up",
		"headers": map[string]string{"Host": "h.example.com"}}
	if !reflect.DeepEqual(node["xhttp-opts"], want) {
		t.Errorf("xhttp-opts 不对: %#v", node["xhttp-opts"])
	}
}

// 导出再导入:全部进阶选项与上下行分离来回一趟不变(下行补全的字段变成显式写法)。
func TestXHTTPExtraRoundTrip(t *testing.T) {
	proxy := substore.Proxy{
		"type": "vless", "name": "全开", "server": "x.example.com", "port": 8443, "uuid": "u-1",
		"network": "xhttp", "tls": true, "servername": "x.example.com", "client-fingerprint": "chrome",
		"alpn": []any{"h2", "http/1.1"},
		"xhttp-opts": map[string]any{
			"path": "/xhttp", "host": "cdn.example.com", "mode": "packet-up",
			"x-padding-bytes": "200-800", "sc-max-each-post-bytes": "2000000",
			"headers":           map[string]any{"X-Token": "abc"},
			"no-grpc-header":    true,
			"reuse-settings":    map[string]any{"max-connections": "3", "h-max-request-times": "600-900", "h-max-reusable-secs": "1800-3000"},
			"download-settings": map[string]any{"server": "203.0.113.10", "port": 8443},
		},
	}
	link, err := substore.NewURIProducer().ProduceOne(proxy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(link, "extra=") {
		t.Fatalf("应带 extra: %s", link)
	}
	node, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	opts := node["xhttp-opts"].(map[string]any)
	for _, k := range []string{"path", "host", "mode", "x-padding-bytes", "sc-max-each-post-bytes", "no-grpc-header"} {
		if !reflect.DeepEqual(opts[k], proxy["xhttp-opts"].(map[string]any)[k]) {
			t.Errorf("%s 来回不一致: %v", k, opts[k])
		}
	}
	if xhttpJSON(opts["reuse-settings"]) != xhttpJSON(proxy["xhttp-opts"].(map[string]any)["reuse-settings"]) {
		t.Errorf("reuse-settings 来回不一致: %v", opts["reuse-settings"])
	}
	if opts["headers"].(map[string]string)["X-Token"] != "abc" {
		t.Errorf("headers 丢了: %v", opts["headers"])
	}
	ds := opts["download-settings"].(map[string]any)
	if ds["server"] != "203.0.113.10" || ds["port"] != 8443 || ds["tls"] != true || ds["servername"] != "x.example.com" ||
		ds["path"] != "/xhttp" || ds["host"] != "cdn.example.com" {
		t.Errorf("download-settings 来回不对: %v", ds)
	}
}
