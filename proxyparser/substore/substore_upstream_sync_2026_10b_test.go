package substore

import (
	"fmt"
	"strings"
	"testing"
)

// 2026-10 第二轮跟上游 Sub-Store 同步(补 09-04 以来漏掉的几项 + a3e61061 之后)的生成行为。

// SS 链接总是写 udp=1/0(上游 7b9d8227)
func TestURIShadowsocksAlwaysWritesUDP(t *testing.T) {
	p := &URIProducer{}
	for udp, want := range map[bool]string{true: "?udp=1#", false: "?udp=0#"} {
		uri, err := p.encodeShadowsocks(Proxy{
			"name": "s", "type": "ss", "server": "ss.example.com", "port": 8388,
			"cipher": "aes-128-gcm", "password": "secret", "udp": udp,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(uri, "ss.example.com:8388"+want) {
			t.Fatalf("udp=%v 应含 %q,实际 %s", udp, want, uri)
		}
	}
}

// sing-box WireGuard 的 allowed_ips:peer → 顶层 → 默认值;字符串按逗号拆;多 peer 没写的继承顶层(上游 11baf128)
func TestSingboxWireGuardAllowedIPsFallback(t *testing.T) {
	p := NewSingboxProducer()
	peerIPs := func(proxy Proxy) [][]string {
		t.Helper()
		out, err := p.wireguardParser(proxy)
		if err != nil {
			t.Fatal(err)
		}
		var got [][]string
		for _, peer := range out["peers"].([]map[string]interface{}) {
			got = append(got, peer["allowed_ips"].([]string))
		}
		return got
	}
	base := func() Proxy {
		return Proxy{"name": "wg", "type": "wireguard", "server": "1.2.3.4", "port": 51820,
			"private-key": "k", "public-key": "pk", "ip": "10.0.0.2"}
	}

	pr := base()
	pr["peers"] = []interface{}{
		map[string]interface{}{"server": "a", "port": 1, "public-key": "x", "allowed-ips": "10.0.0.0/8, 192.168.0.0/16"},
		map[string]interface{}{"server": "b", "port": 2, "public-key": "y"},
	}
	pr["allowed_ips"] = []interface{}{"172.16.0.0/12"}
	got := peerIPs(pr)
	if strings.Join(got[0], ",") != "10.0.0.0/8,192.168.0.0/16" {
		t.Fatalf("peer 里字符串写法应按逗号拆开: %v", got[0])
	}
	if strings.Join(got[1], ",") != "172.16.0.0/12" {
		t.Fatalf("没写的 peer 应继承顶层(下划线写法也认): %v", got[1])
	}

	pr = base()
	pr["allowed-ips"] = []interface{}{}
	if got := peerIPs(pr); strings.Join(got[0], ",") != "0.0.0.0/0" {
		t.Fatalf("空列表应回落默认值: %v", got[0])
	}
}

// sing-box 证书指纹 pin(上游 a3e61061):fingerprint / tls-fingerprint → certificate_sha256(base64);
// 格式不对报错;REALITY 忽略;证书与 sha256 pin 同时存在报冲突
func TestSingboxCertificateSHA256(t *testing.T) {
	p := NewSingboxProducer()
	const hexFP = "d6b4b1a0c6f1a8d3e2b5c4a7f9e8d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6978f"
	trojan := func(extra Proxy) Proxy {
		pr := Proxy{"name": "t", "type": "trojan", "server": "a.com", "port": 443, "password": "x", "sni": "a.com"}
		for k, v := range extra {
			pr[k] = v
		}
		return pr
	}
	tlsOf := func(pr Proxy) (map[string]interface{}, error) {
		out, err := p.trojanParser(pr)
		if err != nil {
			return nil, err
		}
		return out["tls"].(map[string]interface{}), nil
	}

	tls, err := tlsOf(trojan(Proxy{"tls-fingerprint": strings.ToUpper(hexFP)}))
	if err != nil {
		t.Fatal(err)
	}
	if got := tls["certificate_sha256"].([]string)[0]; got != "1rSxoMbxqNPitcSn+ejRwrOk9ebXyLmg8eLTxLWml48=" {
		t.Fatalf("certificate_sha256 = %s", got)
	}
	colon := ""
	for i := 0; i < len(hexFP); i += 2 {
		if i > 0 {
			colon += ":"
		}
		colon += hexFP[i : i+2]
	}
	if _, err := tlsOf(trojan(Proxy{"fingerprint": colon})); err != nil {
		t.Fatalf("带冒号的指纹应认: %v", err)
	}
	if _, err := tlsOf(trojan(Proxy{"fingerprint": "abcd"})); err == nil {
		t.Fatal("格式不对的指纹应报错")
	}
	tls, err = tlsOf(trojan(Proxy{"fingerprint": hexFP, "ca-str": "PEM"}))
	if err != nil || tls["certificate_sha256"] != nil {
		t.Fatalf("已有证书时不转指纹: %v %v", err, tls["certificate_sha256"])
	}
	if _, err := tlsOf(trojan(Proxy{"_certificate_sha256": []interface{}{"x"}, "ca-str": "PEM"})); err == nil {
		t.Fatal("证书与 certificate_sha256 同时存在应报冲突")
	}
	vless, err := p.vlessParser(Proxy{"name": "r", "type": "vless", "server": "a.com", "port": 443, "uuid": "u",
		"tls": true, "servername": "a.com", "fingerprint": hexFP,
		"reality-opts": map[string]interface{}{"public-key": "pk"}})
	if err != nil {
		t.Fatal(err)
	}
	if vless["tls"].(map[string]interface{})["certificate_sha256"] != nil {
		t.Fatal("REALITY 不该带 certificate_sha256")
	}

	// 生产整份配置时,指纹不对的节点被跳过,不影响其余节点
	res, err := p.Produce([]Proxy{trojan(Proxy{"name": "bad", "fingerprint": "zz"}), trojan(Proxy{"name": "good"})}, "internal", &ProduceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprint(res); strings.Contains(s, "bad") || !strings.Contains(s, "good") {
		t.Fatalf("应只剩 good: %s", s)
	}
}

// Loon tls-profile(上游 3078e159 / 07d94ef9 / e08f1b19)
func TestLoonTLSProfile(t *testing.T) {
	p := NewLoonProducer()
	line := func(pr Proxy) string {
		t.Helper()
		out, err := p.ProduceOne(pr, "", &ProduceOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	trojan := func(extra Proxy) Proxy {
		pr := Proxy{"name": "t", "type": "trojan", "server": "a.com", "port": 443, "password": "x"}
		for k, v := range extra {
			pr[k] = v
		}
		return pr
	}
	cases := []struct {
		pr   Proxy
		want string
	}{
		{trojan(Proxy{"client-fingerprint": "chrome"}), ",tls-profile=chrome"},
		{trojan(Proxy{"client-fingerprint": "ios"}), ",tls-profile=safari-ios18"},
		{trojan(Proxy{"client-fingerprint": "chrome", "_loon_tls_profile": "default"}), ",tls-profile=default"},
		{Proxy{"name": "v", "type": "vless", "server": "a.com", "port": 443, "uuid": "u", "tls": true,
			"client-fingerprint": "safari", "sni": "a.com",
			"reality-opts": map[string]interface{}{"public-key": "pk", "support-x25519mlkem768": true}},
			",tls-profile=safari-ios-26"},
	}
	for _, c := range cases {
		if got := line(c.pr); !strings.Contains(got, c.want) {
			t.Fatalf("应含 %s:\n%s", c.want, got)
		}
	}
	if got := line(trojan(Proxy{"client-fingerprint": "firefox"})); strings.Contains(got, "tls-profile") {
		t.Fatalf("认不出的指纹不输出 tls-profile:\n%s", got)
	}
	vmess := Proxy{"name": "m", "type": "vmess", "server": "a.com", "port": 80, "uuid": "u", "cipher": "auto",
		"client-fingerprint": "chrome", "alpn": []interface{}{"h2"}}
	if got := line(vmess); strings.Contains(got, "tls-profile") || strings.Contains(got, "alpn") {
		t.Fatalf("没开 TLS 的 vmess 不输出 tls-profile / alpn:\n%s", got)
	}
	ss := Proxy{"name": "s", "type": "ss", "server": "a.com", "port": 443, "cipher": "aes-128-gcm", "password": "x",
		"client-fingerprint": "chrome", "plugin": "shadow-tls",
		"plugin-opts": map[string]interface{}{"host": "b.com", "password": "pw", "version": 3, "alpn": "h2, http/1.1"}}
	if got := line(ss); !strings.Contains(got, `,tls-profile=chrome,alpn="h2,http/1.1"`) {
		t.Fatalf("shadow-tls 应带 tls-profile 和 plugin-opts 里的 alpn:\n%s", got)
	}
}

// 带 REALITY / finalmask 的 VMess 按查询参数写法导出;非 AEAD 报错(上游 5d7126e9 / 18dfe4c0)
func TestURIVmessQueryStyle(t *testing.T) {
	p := &URIProducer{}
	vm := func(extra Proxy) Proxy {
		pr := Proxy{"name": "vm", "type": "vmess", "server": "2001:db8::1", "port": 443, "uuid": "u",
			"cipher": "chacha20-ietf-poly1305", "alterId": 0, "tls": true, "servername": "a.com",
			"reality-opts": map[string]interface{}{"public-key": "PK", "short-id": "ab"}}
		for k, v := range extra {
			pr[k] = v
		}
		return pr
	}
	uri, err := p.encodeVMess(vm(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vmess://u@[2001:db8::1]:443?", "security=reality", "pbk=PK", "encryption=chacha20-poly1305", "type=tcp"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("应含 %q: %s", want, uri)
		}
	}
	if _, err := p.encodeVMess(vm(Proxy{"alterId": 64})); err == nil {
		t.Fatal("alterId 非 0 应报错")
	}
	if _, err := p.encodeVMess(vm(Proxy{"alterId": 64, "aead": true})); err != nil {
		t.Fatalf("显式 aead 时允许: %v", err)
	}

	// VLESS 的 finalmask:对象序列化成 JSON
	vl, err := p.encodeVLESS(Proxy{"name": "vl", "type": "vless", "server": "a.com", "port": 443, "uuid": "u", "tls": true,
		"_finalmask": map[string]interface{}{"udp": []interface{}{map[string]interface{}{"type": "salamander"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vl, "fm=%7B%22udp%22") {
		t.Fatalf("应带 fm=: %s", vl)
	}
	// 普通 VMess 照旧是 base64 JSON
	plain, _ := p.encodeVMess(Proxy{"name": "p", "type": "vmess", "server": "a.com", "port": 443, "uuid": "u", "cipher": "auto"})
	if strings.Contains(plain, "@") {
		t.Fatalf("普通 VMess 应保持 base64 写法: %s", plain)
	}
}

// QX 把 alpn 编成十六进制的 tls-alpn;已写 tls-alpn 的原样用(上游 54481855)
func TestQXTLSAlpn(t *testing.T) {
	if got := qxEncodeAlpn([]interface{}{"h2", "http/1.1"}); got != "02683208687474702f312e31" {
		t.Fatalf("tls-alpn = %s", got)
	}
	if got := qxEncodeAlpn("h2, h3"); got != "0268320268" + "33" {
		t.Fatalf("逗号分隔也认: %s", got)
	}
	r := NewResult(Proxy{})
	(&QXProducer{}).appendTLSOptions(r, Proxy{"alpn": []interface{}{"h2"}, "tls-alpn": "02aa"})
	if !strings.Contains(r.String(), ",tls-alpn=02aa") || strings.Contains(r.String(), "026832") {
		t.Fatalf("已写 tls-alpn 时原样用: %s", r.String())
	}
}

// sing-box WireGuard endpoint 的 _name / _listen_port / _on_demand / _udp_*(上游 104c9416)
func TestSingboxWireGuardEndpointFields(t *testing.T) {
	out, err := NewSingboxProducer().wireguardParser(Proxy{"name": "wg", "type": "wireguard", "server": "1.2.3.4", "port": 51820,
		"private-key": "k", "public-key": "pk", "ip": "10.0.0.2",
		"_name": "wg0", "_listen_port": "51821", "_on_demand": true, "_udp_nat_max": 4096,
		"_udp_mapping": "endpoint_independent", "_udp_filtering": "bogus"})
	if err != nil {
		t.Fatal(err)
	}
	if out["name"] != "wg0" || out["listen_port"] != int64(51821) || out["on_demand"] != true ||
		out["udp_nat_max"] != int64(4096) || out["udp_mapping"] != "endpoint_independent" {
		t.Fatalf("字段没带上: %v", out)
	}
	if _, ok := out["udp_filtering"]; ok {
		t.Fatalf("不认的取值不输出: %v", out["udp_filtering"])
	}
	out, _ = NewSingboxProducer().wireguardParser(Proxy{"name": "wg", "type": "wireguard", "server": "1.2.3.4", "port": 51820,
		"private-key": "k", "public-key": "pk", "ip": "10.0.0.2", "_listen_port": 70000})
	if _, ok := out["listen_port"]; ok {
		t.Fatal("超过 65535 的端口不输出")
	}
}

// sing-box Tailscale endpoint(上游 tailscaleParser):放进 endpoints,字段改成 sing-box 写法
func TestSingboxTailscaleEndpoint(t *testing.T) {
	res, err := NewSingboxProducer().Produce([]Proxy{{
		"name": "ts", "type": "tailscale", "auth-key": "tskey", "state-dir": "/var/ts", "hostname": "box",
		"advertise-routes": []interface{}{"10.0.0.0/8"}, "_listen_port": 41641, "_on_demand": true,
		"system-interface-mtu": "1280", "ssh-server": map[string]interface{}{"disable-pty": true},
		"control-http-client": "proxy-a", "dialer-proxy": "x",
	}}, "", &ProduceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprint(res)
	for _, want := range []string{`"endpoints"`, `"type": "tailscale"`, `"auth_key": "tskey"`, `"state_directory": "/var/ts"`,
		`"listen_port": 41641`, `"on_demand": true`, `"system_interface_mtu": 1280`, `"disable_pty": true`, `"advertise_routes"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("应含 %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"detour"`) {
		t.Fatalf("设了 control-http-client 时不写 detour:\n%s", out)
	}
}
