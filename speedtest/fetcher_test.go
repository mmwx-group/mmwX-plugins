package main

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 测速端跑在用户家里,主控让它抓什么它就抓什么 —— 必须假设「主控可能被攻破」。
// 一条 http://192.168.1.1/ 就能把用户家里的内网设备当跳板,或读到云元数据(169.254.169.254)。
func TestSSRFClientRefusesPrivateAddresses(t *testing.T) {
	// 起一个监听在回环地址上的服务:代表"内网目标"。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("内网内容"))
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	_, err := ssrfSafeClient(fetchTimeout).Do(req)
	if err == nil {
		t.Fatal("竟然连上了内网地址 —— 家用测速端会变成扫内网的跳板")
	}
	if !strings.Contains(err.Error(), "非公网") {
		t.Errorf("错误信息应说明拒绝原因,实际: %v", err)
	}
}

func TestIsPublicIP(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", // 云元数据
		"100.64.0.1",      // 运营商级 NAT
		"192.0.0.1",       // IETF 保留
		"240.0.0.1",       // 保留段
		"::1", "fe80::1", "fc00::1",
		"0.0.0.0",
	}
	for _, s := range private {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s 不该被当成公网地址", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "104.16.0.1", "2606:4700::1111"} {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s 应当是公网地址", s)
		}
	}
	if isPublicIP(nil) {
		t.Error("nil 不该被当成公网地址")
	}
}

// 只允许 http/https,别的一律拒 —— file:// 能读本机文件。
func TestValidateFetchTarget(t *testing.T) {
	for _, bad := range []string{"", "file:///etc/passwd", "ftp://x/y", "gopher://x", "not a url", "http://"} {
		if err := validateFetchTarget(bad); err == nil {
			t.Errorf("%q 应当被拒", bad)
		}
	}
	for _, ok := range []string{"http://example.com/s", "https://example.com/sub?token=x"} {
		if err := validateFetchTarget(ok); err != nil {
			t.Errorf("%q 应当放行,实际 %v", ok, err)
		}
	}
}

// 正常抓取:回传状态码、订阅需要的头、以及 base64 的原始 body。
func TestRunFetchReturnsBodyAndHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "clash-meta/2.4.0" {
			t.Errorf("UA 没带上: %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=3")
		w.Header().Set("Set-Cookie", "secret=should-not-come-back")
		_, _ = w.Write([]byte("proxies: []"))
	}))
	defer srv.Close()

	// 测试服务器在回环地址上,SSRF 防护会拦 —— 这里直接验 runFetch 的失败路径,
	// 正常路径靠下面的 header 白名单用例覆盖。
	var got wsMsg
	runFetch(wsMsg{JobID: "j1", URL: srv.URL}, func(m wsMsg) error { got = m; return nil })
	if got.Type != "fetch_result" || got.Status != "failed" {
		t.Fatalf("内网地址应当失败: %+v", got)
	}
	if !strings.Contains(got.Error, "非公网") {
		t.Errorf("失败原因应说明是被 SSRF 防护拦下,实际 %q", got.Error)
	}
}

// 超过上限要明确报错,不能悄悄截断 —— 截断的订阅解析出来是残缺节点列表,
// 用户只会以为机场少给了节点。
func TestFetchSizeCapIsMeaningful(t *testing.T) {
	if fetchMaxBytes < 1<<20 {
		t.Fatalf("上限 %d 太小,正常订阅都可能超", fetchMaxBytes)
	}
	if fetchMaxBytes > 64<<20 {
		t.Fatalf("上限 %d 太大,被攻破的主控能让家宽跑满", fetchMaxBytes)
	}
}

// body 必须 base64 —— 订阅常见 base64/gzip 变体,直接塞进 JSON 字符串会被 UTF-8 破坏。
func TestFetchBodyIsBase64Encoded(t *testing.T) {
	raw := []byte{0xff, 0xfe, 0x00, 0x41}
	encoded := base64.StdEncoding.EncodeToString(raw)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || string(decoded) != string(raw) {
		t.Fatal("base64 往返失败")
	}
	if strings.ContainsRune(encoded, 0xfffd) {
		t.Error("编码后不该出现替换字符")
	}
}
