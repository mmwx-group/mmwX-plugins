package substore

import (
	"strings"
	"testing"
)

func produceSurgeVLESS(t *testing.T, proxy Proxy, enabled bool) string {
	t.Helper()
	out, err := NewSurgeProducer().Produce([]Proxy{proxy}, "", &ProduceOptions{SurgeVLESS: enabled})
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	return strings.TrimSpace(out.(string))
}

func vlessRealityProxy() Proxy {
	return Proxy{
		"name": "jp", "type": "vless", "server": "1.2.3.4", "port": 443,
		"uuid": "0b5a8a5e-1c39-4c1e-9f0e-6f4f4b2b9a11", "network": "tcp", "tls": true,
		"flow": "xtls-rprx-vision", "servername": "www.example.com", "client-fingerprint": "chrome",
		"skip-cert-verify": false,
		"reality-opts":     map[string]interface{}{"public-key": "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "short-id": "6ba85179e30d4fc2"},
	}
}

// 默认不输出:旧版 Surge 遇到 vless 行会整份配置拒载。
func TestSurgeVLESSOffByDefault(t *testing.T) {
	if got := produceSurgeVLESS(t, vlessRealityProxy(), false); got != "" {
		t.Fatalf("开关关闭时不该输出 VLESS: %s", got)
	}
	out, err := NewSurgeProducer().Produce([]Proxy{vlessRealityProxy()}, "", nil)
	if err != nil || strings.TrimSpace(out.(string)) != "" {
		t.Fatalf("opts=nil 时不该输出 VLESS: %v %v", out, err)
	}
}

func TestSurgeVLESSRealityVision(t *testing.T) {
	got := produceSurgeVLESS(t, vlessRealityProxy(), true)
	want := "jp=vless,1.2.3.4,443,username=0b5a8a5e-1c39-4c1e-9f0e-6f4f4b2b9a11,flow=xtls-rprx-vision," +
		"reality-public-key=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw,reality-short-id=6ba85179e30d4fc2,sni=www.example.com"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSurgeVLESSWebSocketTLS(t *testing.T) {
	got := produceSurgeVLESS(t, Proxy{
		"name": "ws", "type": "vless", "server": "a.example.com", "port": 443, "uuid": "u1",
		"network": "ws", "tls": true, "servername": "a.example.com",
		"ws-opts": map[string]interface{}{"path": "/vl", "headers": map[string]interface{}{"Host": "a.example.com"}},
	}, true)
	want := `ws=vless,a.example.com,443,username=u1,ws=true,ws-path=/vl,ws-headers=Host:"a.example.com",tls=true,sni=a.example.com`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSurgeVLESSGRPCReality(t *testing.T) {
	p := vlessRealityProxy()
	p["network"] = "grpc"
	delete(p, "flow")
	p["grpc-opts"] = map[string]interface{}{"grpc-service-name": "mygrpc"}
	got := produceSurgeVLESS(t, p, true)
	if !strings.Contains(got, ",grpc=true,grpc-service-name=mygrpc,reality-public-key=") || strings.Contains(got, "tls=true") {
		t.Fatalf("gRPC + REALITY: %s", got)
	}
}

func TestSurgeVLESSPlainTCP(t *testing.T) {
	got := produceSurgeVLESS(t, Proxy{"name": "raw", "type": "vless", "server": "1.1.1.1", "port": 8080, "uuid": "u2", "network": "tcp"}, true)
	if got != "raw=vless,1.1.1.1,8080,username=u2" {
		t.Fatalf("plain: %s", got)
	}
}

// Surge 不支持的组合跳过,不能写出一行让 Surge 拒载的配置。
func TestSurgeVLESSSkipsUnsupported(t *testing.T) {
	cases := map[string]Proxy{}
	x := vlessRealityProxy()
	x["network"] = "xhttp"
	cases["xhttp"] = x
	e := vlessRealityProxy()
	e["encryption"] = "mlkem768x25519plus.native.0rtt.abc"
	cases["encryption"] = e
	cases["vision-over-ws"] = Proxy{"name": "w", "type": "vless", "server": "a", "port": 443, "uuid": "u", "network": "ws", "tls": true, "flow": "xtls-rprx-vision"}
	cases["vision-no-tls"] = Proxy{"name": "v", "type": "vless", "server": "a", "port": 443, "uuid": "u", "network": "tcp", "flow": "xtls-rprx-vision"}
	cases["grpc-no-tls"] = Proxy{"name": "g", "type": "vless", "server": "a", "port": 443, "uuid": "u", "network": "grpc"}
	cases["httpupgrade"] = Proxy{"name": "h", "type": "vless", "server": "a", "port": 443, "uuid": "u", "network": "ws", "tls": true,
		"ws-opts": map[string]interface{}{"path": "/", "v2ray-http-upgrade": true}}
	for name, p := range cases {
		if got := produceSurgeVLESS(t, p, true); got != "" {
			t.Errorf("%s 应跳过,实际 %s", name, got)
		}
	}
}

// 整份 Surge 配置(BuildCompleteSurgeConfig)同样按开关:关着时 VLESS 节点从组里摘掉,开着时保留。
func TestBuildCompleteSurgeConfigVLESSSwitch(t *testing.T) {
	cfg := &ClashConfig{ProxyGroups: []ClashProxyGroup{{Name: "G", Type: "select", Proxies: []string{"jp", "DIRECT"}}}}
	off, err := BuildCompleteSurgeConfig(cfg, []Proxy{vlessRealityProxy()}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "=vless,") || strings.Contains(off, "jp") {
		t.Fatalf("关闭时不该出现 VLESS 节点或引用:\n%s", off)
	}
	withDefaults := DefaultSurgeTemplateConfig()
	withDefaults.SurgeVLESS = true
	on, err := BuildCompleteSurgeConfig(cfg, []Proxy{vlessRealityProxy()}, withDefaults, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(on, "jp=vless,1.2.3.4,443") {
		t.Fatalf("打开时应输出 VLESS:\n%s", on)
	}
	// 从默认设置出发,除 VLESS 那几行外 [General] 与传 nil 完全相同。
	if strings.SplitN(on, "[Proxy]", 2)[0] != strings.SplitN(off, "[Proxy]", 2)[0] {
		t.Fatalf("DefaultSurgeTemplateConfig 的 [General] 与 nil 不同")
	}
}

// 与 Sub-Store 091e6f8d 对齐的四项:WS + REALITY、gRPC + Vision 跳过;raw / none 按 RAW;gRPC 的 mode / authority 照写。
func TestSurgeVLESSUpstreamAlign(t *testing.T) {
	wsReality := vlessRealityProxy()
	wsReality["network"] = "ws"
	delete(wsReality, "flow")
	if got := produceSurgeVLESS(t, wsReality, true); got != "" {
		t.Errorf("WS + REALITY 应该跳过: %s", got)
	}

	grpcVision := vlessRealityProxy()
	grpcVision["network"] = "grpc"
	if got := produceSurgeVLESS(t, grpcVision, true); got != "" {
		t.Errorf("gRPC + Vision 应该跳过: %s", got)
	}

	raw := vlessRealityProxy()
	raw["network"] = "raw"
	if got := produceSurgeVLESS(t, raw, true); !strings.HasPrefix(got, "jp=vless,1.2.3.4,443,username=") || !strings.Contains(got, ",flow=xtls-rprx-vision,") {
		t.Errorf("raw 应按 RAW 输出: %s", got)
	}

	grpc := vlessRealityProxy()
	grpc["network"] = "grpc"
	delete(grpc, "flow")
	grpc["grpc-opts"] = map[string]interface{}{"grpc-service-name": "svc", "_grpc-type": "multi", "_grpc-authority": "a.example.com"}
	if got := produceSurgeVLESS(t, grpc, true); !strings.Contains(got, ",grpc=true,grpc-service-name=svc,grpc-mode=multi,grpc-authority=a.example.com,") {
		t.Errorf("gRPC mode / authority: %s", got)
	}
	grpc["grpc-opts"] = map[string]interface{}{"grpc-service-name": "svc", "_grpc-type": "guna"}
	if got := produceSurgeVLESS(t, grpc, true); strings.Contains(got, "grpc-mode") {
		t.Errorf("不认识的 mode 不该写: %s", got)
	}
}
