package substore

import (
	"strings"
	"testing"
)

func surgemacProduce(t *testing.T, proxy Proxy, opts *ProduceOptions) string {
	t.Helper()
	p := NewSurgeMacProducer()
	out, err := p.Produce([]Proxy{proxy}, "", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := out.(string)
	if !ok {
		t.Fatalf("expected string output, got %T", out)
	}
	return strings.TrimRight(s, "\n")
}

// external 节点应原样输出，并镜像 JS external() 的字段顺序与 udp-relay。
func TestSurgemacExternalBasic(t *testing.T) {
	got := surgemacProduce(t, Proxy{
		"name":           "ext",
		"type":           "external",
		"exec":           "/usr/local/bin/foo",
		"local-port":     12345,
		"args":           []string{"-a", "-b"},
		"addresses":      []string{"1.2.3.4"},
		"no-error-alert": true,
		"udp":            true,
		"tfo":            true,
		"test-url":       "http://www.gstatic.com/generate_204",
		"block-quic":     "on",
	}, nil)
	want := `ext=external,exec="/usr/local/bin/foo",local-port=12345,args="-a",args="-b",addresses=1.2.3.4,no-error-alert=true,udp-relay=true,tfo=true,test-url=http://www.gstatic.com/generate_204,block-quic=on`
	if got != want {
		t.Errorf("external mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// external() 中 udp-relay 取自 proxy.udp，缺省时不应输出该字段。
func TestSurgemacExternalNoUdpRelayWhenAbsent(t *testing.T) {
	got := surgemacProduce(t, Proxy{
		"name":       "ext",
		"type":       "external",
		"exec":       "/usr/local/bin/foo",
		"local-port": 1080,
	}, nil)
	want := `ext=external,exec="/usr/local/bin/foo",local-port=1080`
	if got != want {
		t.Errorf("external mismatch:\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(got, "udp-relay") {
		t.Errorf("did not expect udp-relay: %s", got)
	}
}

// tfo 缺省但存在 fast-open 时，external() 应回退用 fast-open。
func TestSurgemacExternalFastOpenFallback(t *testing.T) {
	got := surgemacProduce(t, Proxy{
		"name":       "ext",
		"type":       "external",
		"exec":       "/usr/local/bin/foo",
		"local-port": 1080,
		"fast-open":  true,
	}, nil)
	if !strings.Contains(got, ",tfo=true") {
		t.Errorf("expected tfo from fast-open, got: %s", got)
	}
}

// exec 或 local-port 缺失时应报错（节点被过滤掉）。
func TestSurgemacExternalRequiresExecAndPort(t *testing.T) {
	p := NewSurgeMacProducer()
	// 缺 local-port
	if _, err := p.ProduceOne(Proxy{
		"name": "ext", "type": "external", "exec": "/usr/local/bin/foo",
	}, "", nil); err == nil {
		t.Errorf("expected error when local-port missing")
	}
	// 缺 exec
	if _, err := p.ProduceOne(Proxy{
		"name": "ext", "type": "external", "local-port": 1080,
	}, "", nil); err == nil {
		t.Errorf("expected error when exec missing")
	}
}

// 受 Surge 支持的类型应直接委托给 surge producer（与 Surge 输出一致）。
func TestSurgemacDelegatesToSurge(t *testing.T) {
	proxy := Proxy{
		"name": "ss", "type": "ss", "server": "1.2.3.4", "port": 8388,
		"cipher": "aes-128-gcm", "password": "pw",
	}
	macOut := surgemacProduce(t, proxy, nil)

	surge := NewSurgeProducer()
	sOut, err := surge.Produce([]Proxy{proxy}, "", nil)
	if err != nil {
		t.Fatalf("surge produce error: %v", err)
	}
	want := strings.TrimRight(sOut.(string), "\n")
	if macOut != want {
		t.Errorf("surgemac should match surge for ss:\n got: %s\nwant: %s", macOut, want)
	}
}

// Surge 不支持的类型 + UseMihomoExternal 时，应回退到 mihomo external，
// 输出 type=external 且 udp-relay=true（external_proxy.udp=true）。
func TestSurgemacMihomoFallback(t *testing.T) {
	got := surgemacProduce(t, Proxy{
		"name":   "vl",
		"type":   "vless",
		"server": "1.2.3.4",
		"port":   443,
		"uuid":   "11111111-1111-1111-1111-111111111111",
	}, &ProduceOptions{UseMihomoExternal: true})
	if !strings.Contains(got, "vl=external,") {
		t.Errorf("expected mihomo external output, got: %s", got)
	}
	if !strings.Contains(got, "exec=\"/usr/local/bin/mihomo\"") {
		t.Errorf("expected default mihomo exec, got: %s", got)
	}
	if !strings.Contains(got, ",udp-relay=true") {
		t.Errorf("expected udp-relay=true from mihomo external_proxy.udp, got: %s", got)
	}
	// server 为 IP，应作为 addresses 输出
	if !strings.Contains(got, ",addresses=1.2.3.4") {
		t.Errorf("expected addresses=1.2.3.4, got: %s", got)
	}
}

// Surge 不支持的类型且未启用 mihomo 回退时，节点应被过滤（输出为空）。
func TestSurgemacUnsupportedFilteredWithoutMihomo(t *testing.T) {
	got := surgemacProduce(t, Proxy{
		"name":   "vl",
		"type":   "vless",
		"server": "1.2.3.4",
		"port":   443,
		"uuid":   "11111111-1111-1111-1111-111111111111",
	}, nil)
	if got != "" {
		t.Errorf("expected empty output for unsupported type without mihomo, got: %s", got)
	}
}

// proxy._mihomoExternal 标记应直接走 mihomo external（即便类型本可被 surge 支持）。
func TestSurgemacMihomoExternalDirectDispatch(t *testing.T) {
	got := surgemacProduce(t, Proxy{
		"name":            "ss",
		"type":            "ss",
		"server":          "1.2.3.4",
		"port":            8388,
		"cipher":          "aes-128-gcm",
		"password":        "pw",
		"_mihomoExternal": true,
	}, nil)
	if !strings.Contains(got, "ss=external,") {
		t.Errorf("expected direct mihomo external dispatch, got: %s", got)
	}
}
