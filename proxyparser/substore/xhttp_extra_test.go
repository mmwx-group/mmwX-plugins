package substore

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// XHTTP 进阶选项写进 vless:// 的 extra(Xray / v2rayN / v2rayNG 的写法)。

// xhttpLinkParams 拆出链接的查询参数与解析后的 extra。
func xhttpLinkParams(t *testing.T, link string) (url.Values, map[string]interface{}) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("链接解析失败: %v\n%s", err, link)
	}
	q := u.Query()
	var extra map[string]interface{}
	if s := q.Get("extra"); s != "" {
		if err := json.Unmarshal([]byte(s), &extra); err != nil {
			t.Fatalf("extra 不是 JSON: %v\n%s", err, s)
		}
	}
	return q, extra
}

func jsonEqual(t *testing.T, label string, got, want interface{}) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	var gv, wv interface{}
	_ = json.Unmarshal(g, &gv)
	_ = json.Unmarshal(w, &wv)
	if !reflect.DeepEqual(gv, wv) {
		t.Errorf("%s 不对:\n got %s\nwant %s", label, g, w)
	}
}

// 没有进阶选项时,链接与改动前逐字相同。
func TestXHTTPURINoAdvancedUnchanged(t *testing.T) {
	cases := []struct {
		proxy Proxy
		want  string
	}{
		{
			Proxy{"type": "vless", "name": "xh 1", "server": "x.example.com", "port": 8443, "uuid": "u-1", "tls": true,
				"servername": "x.example.com", "network": "xhttp", "mode": "packet-up", "alpn": []interface{}{"h2", "http/1.1"},
				"client-fingerprint": "chrome",
				"xhttp-opts":         map[string]interface{}{"path": "/xhttp", "headers": map[string]interface{}{"Host": "cdn.example.com"}}},
			"vless://u-1@x.example.com:8443?alpn=h2%2Chttp%2F1.1&fp=chrome&host=cdn.example.com&mode=packet-up&path=%2Fxhttp&security=tls&sni=x.example.com&type=xhttp#xh%201",
		},
		{
			Proxy{"type": "vless", "name": "xh2", "server": "x.example.com", "port": 443, "uuid": "u-2", "network": "xhttp",
				"reality-opts": map[string]interface{}{"public-key": "PBK", "short-id": "ab"}, "client-fingerprint": "chrome",
				"servername": "www.apple.com", "xhttp-opts": map[string]interface{}{"path": "/p"}},
			"vless://u-2@x.example.com:443?fp=chrome&mode=auto&path=%2Fp&pbk=PBK&security=reality&sid=ab&sni=www.apple.com&type=xhttp#xh2",
		},
	}
	for _, c := range cases {
		if got := produceURI(t, c.proxy); got != c.want {
			t.Errorf("链接变了:\n got %s\nwant %s", got, c.want)
		}
	}
}

// mode 先读 xhttp-opts.mode,没有再读顶层,都没有是 auto;host 先读 xhttp-opts.host,再读 headers.Host。
func TestXHTTPURIModeAndHost(t *testing.T) {
	base := func() Proxy {
		return Proxy{"type": "vless", "name": "n", "server": "s.example.com", "port": 443, "uuid": "u", "tls": true, "network": "xhttp"}
	}
	p := base()
	p["mode"] = "stream-up"
	p["xhttp-opts"] = map[string]interface{}{"path": "/a", "mode": "packet-up", "host": "h.example.com",
		"headers": map[string]interface{}{"Host": "other.example.com"}}
	q, extra := xhttpLinkParams(t, produceURI(t, p))
	if q.Get("mode") != "packet-up" || q.Get("host") != "h.example.com" {
		t.Errorf("mode/host 取错: mode=%q host=%q", q.Get("mode"), q.Get("host"))
	}
	if extra != nil {
		t.Errorf("headers 只有 Host 时不该有 extra: %v", extra)
	}

	p = base()
	p["mode"] = "stream-up"
	p["xhttp-opts"] = map[string]interface{}{"path": "/a"}
	if q, _ := xhttpLinkParams(t, produceURI(t, p)); q.Get("mode") != "stream-up" {
		t.Errorf("没有 xhttp-opts.mode 时应读顶层: %q", q.Get("mode"))
	}

	p = base()
	p["xhttp-opts"] = map[string]interface{}{"path": "/a"}
	if q, _ := xhttpLinkParams(t, produceURI(t, p)); q.Get("mode") != "auto" {
		t.Errorf("都没写时应是 auto: %q", q.Get("mode"))
	}
}

// 全部进阶选项 + 上下行分离(只写了 server / port,其余按主连接补全)。
func TestXHTTPURIExtraAllFields(t *testing.T) {
	p := Proxy{
		"type": "vless", "name": "全开", "server": "x.example.com", "port": 8443, "uuid": "u-1",
		"network": "xhttp", "mode": "packet-up", "tls": true, "servername": "x.example.com",
		"alpn": []interface{}{"h2", "http/1.1"}, "client-fingerprint": "chrome",
		"tls-fingerprint": "AB:CD", "skip-cert-verify": true,
		"xhttp-opts": map[string]interface{}{
			"path": "/xhttp", "host": "cdn.example.com", "mode": "packet-up",
			"x-padding-bytes":        "200-800",
			"sc-max-each-post-bytes": "2000000",
			"headers":                map[string]interface{}{"X-Token": "abc def"},
			"no-grpc-header":         true,
			"reuse-settings": map[string]interface{}{
				"max-connections": "3", "h-max-request-times": "600-900", "h-max-reusable-secs": "1800-3000",
				"c-max-reuse-times": 8, "h-keep-alive-period": "30",
			},
			"download-settings": map[string]interface{}{"server": "203.0.113.10", "port": 8443},
		},
	}
	link := produceURI(t, p)
	if strings.Contains(link, "+") {
		t.Errorf("extra 里的空格应写成 %%20: %s", link)
	}
	q, extra := xhttpLinkParams(t, link)
	if q.Get("type") != "xhttp" || q.Get("path") != "/xhttp" || q.Get("host") != "cdn.example.com" || q.Get("mode") != "packet-up" {
		t.Errorf("基本参数不对: %v", q)
	}
	xmux := map[string]interface{}{
		"maxConnections": "3", "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "1800-3000",
		"cMaxReuseTimes": 8, "hKeepAlivePeriod": 30,
	}
	want := map[string]interface{}{
		"headers":            map[string]interface{}{"X-Token": "abc def"},
		"noGRPCHeader":       true,
		"xPaddingBytes":      "200-800",
		"scMaxEachPostBytes": "2000000",
		"xmux":               xmux,
		"downloadSettings": map[string]interface{}{
			"address":  "203.0.113.10",
			"port":     8443,
			"network":  "xhttp",
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName": "x.example.com", "alpn": []string{"h2", "http/1.1"},
				"fingerprint": "chrome", "pinnedPeerCertSha256": "AB:CD",
			},
			"xhttpSettings": map[string]interface{}{
				"path": "/xhttp", "host": "cdn.example.com", "mode": "packet-up",
				"headers":            map[string]interface{}{"X-Token": "abc def"},
				"noGRPCHeader":       true,
				"xPaddingBytes":      "200-800",
				"scMaxEachPostBytes": "2000000",
				"xmux":               xmux,
			},
		},
	}
	jsonEqual(t, "extra", extra, want)
}

// 上下行分离:download-settings 写了的覆盖主连接(REALITY、SNI、path、headers、复用),没写的沿用。
func TestXHTTPURIDownloadOverridesAndReality(t *testing.T) {
	p := Proxy{
		"type": "vless", "name": "r", "server": "x.example.com", "port": 443, "uuid": "u",
		"network": "xhttp", "tls": true, "servername": "www.apple.com",
		"reality-opts": map[string]interface{}{"public-key": "PBK", "short-id": "ab"},
		"xhttp-opts": map[string]interface{}{
			"path": "/p", "mode": "stream-up",
			"reuse-settings": map[string]interface{}{"max-concurrency": "16-32"},
			"download-settings": map[string]interface{}{
				"server": "dl.example.com", "path": "/down",
				"headers":        map[string]interface{}{"X-Down": "1"},
				"reuse-settings": map[string]interface{}{"max-connections": "2"},
				"reality-opts":   map[string]interface{}{"public-key": "PBK2", "short-id": "cd"},
				"servername":     "www.microsoft.com", "client-fingerprint": "firefox",
			},
		},
	}
	_, extra := xhttpLinkParams(t, produceURI(t, p))
	want := map[string]interface{}{
		"xmux": map[string]interface{}{"maxConcurrency": "16-32"},
		"downloadSettings": map[string]interface{}{
			"address": "dl.example.com", "port": 443, "network": "xhttp", "security": "reality",
			"realitySettings": map[string]interface{}{
				"serverName": "www.microsoft.com", "fingerprint": "firefox", "publicKey": "PBK2", "shortId": "cd",
			},
			"xhttpSettings": map[string]interface{}{
				"path": "/down", "mode": "stream-up",
				"headers": map[string]interface{}{"X-Down": "1"},
				"xmux":    map[string]interface{}{"maxConnections": "2"},
			},
		},
	}
	jsonEqual(t, "extra", extra, want)

	// 只写 server 时 REALITY 整份沿用主连接,指纹没写按 chrome
	opts := p["xhttp-opts"].(map[string]interface{})
	opts["download-settings"] = map[string]interface{}{"server": "198.51.100.7"}
	_, extra = xhttpLinkParams(t, produceURI(t, p))
	dl := extra["downloadSettings"].(map[string]interface{})
	jsonEqual(t, "realitySettings", dl["realitySettings"], map[string]interface{}{
		"serverName": "www.apple.com", "fingerprint": "chrome", "publicKey": "PBK", "shortId": "ab",
	})

	// 主连接不加密时下行也是 none
	plain := Proxy{"type": "vless", "name": "plain", "server": "x.example.com", "port": 80, "uuid": "u", "network": "xhttp",
		"xhttp-opts": map[string]interface{}{"path": "/p", "download-settings": map[string]interface{}{"port": 8080}}}
	_, extra = xhttpLinkParams(t, produceURI(t, plain))
	dl = extra["downloadSettings"].(map[string]interface{})
	if dl["security"] != "none" || dl["address"] != "x.example.com" || dl["port"] != float64(8080) {
		t.Errorf("不加密的下行不对: %v", dl)
	}
}

// 没有证书指纹、跳过校验时才写 allowInsecure。
func TestXHTTPURIDownloadAllowInsecure(t *testing.T) {
	p := Proxy{"type": "vless", "name": "n", "server": "x.example.com", "port": 443, "uuid": "u", "network": "xhttp",
		"tls": true, "skip-cert-verify": true,
		"xhttp-opts": map[string]interface{}{"path": "/p", "download-settings": map[string]interface{}{"server": "1.2.3.4"}}}
	_, extra := xhttpLinkParams(t, produceURI(t, p))
	ts := extra["downloadSettings"].(map[string]interface{})["tlsSettings"].(map[string]interface{})
	if ts["allowInsecure"] != true {
		t.Errorf("应写 allowInsecure: %v", ts)
	}
}

// Stash:放行 VLESS xhttp(含 REALITY),download-settings 换成 Stash 字段名,去掉 reuse-settings。
func TestStashXHTTP(t *testing.T) {
	opts := map[string]interface{}{
		"path": "/p", "host": "cdn.example.com", "x-padding-bytes": "100-1000",
		"reuse-settings": map[string]interface{}{"max-connections": "3"},
		"download-settings": map[string]interface{}{
			"server": "1.2.3.4", "servername": "x.example.com", "fingerprint": "AB",
			"reuse-settings": map[string]interface{}{"max-connections": "2"},
		},
	}
	proxies := []Proxy{
		{"type": "vless", "name": "xh", "server": "x.example.com", "port": 443, "uuid": "u", "tls": true,
			"network": "xhttp", "mode": "packet-up", "xhttp-opts": opts},
		{"type": "vless", "name": "xr", "server": "x.example.com", "port": 443, "uuid": "u", "tls": true,
			"network": "xhttp", "reality-opts": map[string]interface{}{"public-key": "P"}, "xhttp-opts": map[string]interface{}{"path": "/r"}},
		{"type": "vmess", "name": "vm", "server": "x.example.com", "port": 443, "uuid": "u", "cipher": "auto", "network": "xhttp"},
	}
	out, err := NewStashProducer().Produce(proxies, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	list := out.([]Proxy)
	if len(list) != 2 {
		t.Fatalf("应输出两个 VLESS xhttp 节点(vmess 不行): %d", len(list))
	}
	got := list[0]["xhttp-opts"].(map[string]interface{})
	if _, has := got["reuse-settings"]; has {
		t.Errorf("Stash 没有 reuse-settings: %v", got)
	}
	if got["mode"] != "packet-up" || got["x-padding-bytes"] != "100-1000" || got["host"] != "cdn.example.com" {
		t.Errorf("xhttp-opts 不对: %v", got)
	}
	jsonEqual(t, "download-settings", got["download-settings"], map[string]interface{}{
		"server": "1.2.3.4", "sni": "x.example.com", "server-cert-fingerprint": "AB",
	})
	// 不改动传入的节点
	if _, has := opts["reuse-settings"]; !has {
		t.Errorf("传入节点的 xhttp-opts 被改了")
	}
}

// ClashMeta(mihomo):VLESS xhttp 原样输出,其它协议的 xhttp 仍跳过。
func TestClashMetaXHTTP(t *testing.T) {
	opts := map[string]interface{}{"path": "/p", "x-padding-bytes": "100-1000",
		"download-settings": map[string]interface{}{"server": "1.2.3.4"}}
	proxies := []Proxy{
		{"type": "vless", "name": "xh", "server": "x.example.com", "port": 443, "uuid": "u", "tls": true, "network": "xhttp", "xhttp-opts": opts},
		{"type": "vmess", "name": "vm", "server": "x.example.com", "port": 443, "uuid": "u", "cipher": "auto", "network": "xhttp"},
	}
	out, err := NewClashMetaProducer().Produce(proxies, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	list := out.([]Proxy)
	if len(list) != 1 || list[0]["name"] != "xh" {
		t.Fatalf("应只输出 VLESS xhttp: %v", list)
	}
	jsonEqual(t, "xhttp-opts", list[0]["xhttp-opts"], opts)
}

// Shadowrocket:xhttp-opts.host 也写进 obfsParam(以前只认 headers.Host)。
func TestShadowrocketXHTTPHost(t *testing.T) {
	p := Proxy{"type": "vless", "name": "xh", "server": "x.example.com", "port": 443, "uuid": "u", "tls": true,
		"network": "xhttp", "xhttp-opts": map[string]interface{}{"path": "/p", "host": "cdn.example.com"}}
	out, err := NewShadowrocketProducer().Produce([]Proxy{p}, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := out.([]Proxy)[0]
	if got["obfsParam"] != "cdn.example.com" || got["path"] != "/p" || got["obfs"] != "xhttp" {
		t.Errorf("Shadowrocket xhttp 不对: %v", got)
	}
}
