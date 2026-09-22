package substore

import (
	"strings"
	"testing"
)

func loonWireGuardLine(t *testing.T, proxy Proxy) string {
	t.Helper()
	line, err := NewLoonProducer().ProduceOne(proxy, "", nil)
	if err != nil {
		t.Fatalf("loon produce: %v", err)
	}
	return line
}

func TestLoonWireGuardDefaultAllowedIPsFollowIPv6(t *testing.T) {
	dual := loonWireGuardLine(t, masterWireGuardProxy())
	for _, want := range []string{
		"wg-in=wireguard", ",interface-ip=10.66.0.5", ",interface-ipv6=fd00:66::5",
		`,private-key="cHJpdmF0ZStrZXkvd2l0aD1zeW1ib2xzKysrKysrKys="`, ",mtu=1420",
		`public-key="c2VydmVyK3B1Yi9rZXk9PT09PT09PT09PT09PT09PT0="`,
		`allowed-ips="0.0.0.0/0,::/0"`, "endpoint=1.2.3.4:51820",
	} {
		if !strings.Contains(dual, want) {
			t.Errorf("双栈节点缺少 %q:\n%s", want, dual)
		}
	}
	if strings.Contains(dual, "keepalive") || strings.Contains(dual, "preshared-key") {
		t.Errorf("没配 keepalive / psk 时不应输出:\n%s", dual)
	}

	v4 := masterWireGuardProxy()
	delete(v4, "ipv6")
	line := loonWireGuardLine(t, v4)
	if !strings.Contains(line, `allowed-ips="0.0.0.0/0"`) || strings.Contains(line, "::/0") {
		t.Errorf("只有 v4 时默认 allowed-ips 不该带 ::/0:\n%s", line)
	}
	if strings.Contains(line, "interface-ipv6") {
		t.Errorf("没有 ipv6 时不应输出 interface-ipv6:\n%s", line)
	}

	// 显式 allowed-ips 覆盖默认值(即使带 ipv6)。主控对只有 v4 的服务器会显式写,
	// YAML 读回来是 []interface{},Go 里直接构造是 []string,手写的是逗号串,三种都要认。
	for _, ips := range []interface{}{[]interface{}{"0.0.0.0/0"}, []string{"0.0.0.0/0"}, "0.0.0.0/0"} {
		p := masterWireGuardProxy()
		p["allowed-ips"] = ips
		if line := loonWireGuardLine(t, p); !strings.Contains(line, `allowed-ips="0.0.0.0/0",`) {
			t.Errorf("显式 allowed-ips(%T)应覆盖默认值:\n%s", ips, line)
		}
	}
}

func TestLoonWireGuardOptionalFieldsOnlyWhenSet(t *testing.T) {
	p := masterWireGuardProxy()
	p["persistent-keepalive"] = 25
	p["keepalive"] = 25
	line := loonWireGuardLine(t, p)
	if strings.Count(line, "keepalive=") != 1 || !strings.Contains(line, ",keepalive=25") {
		t.Errorf("keepalive 两种写法都在时只该输出一次:\n%s", line)
	}

	p = masterWireGuardProxy()
	p["persistent-keepalive"] = 0
	p["mtu"] = 0
	line = loonWireGuardLine(t, p)
	if strings.Contains(line, "keepalive") || strings.Contains(line, "mtu=") {
		t.Errorf("零值 keepalive / mtu 不应输出:\n%s", line)
	}
}

// Loon 的 WG endpoint 能不能写成 [v6]:port 没有官方依据,改错了 Loon 会整行解析失败。
// 这里按规格**不改语法**,只把现状钉住:纯 v6 服务器由主控优先下发域名来规避。
func TestLoonWireGuardIPv6EndpointSyntaxUnchanged(t *testing.T) {
	p := masterWireGuardProxy()
	p["server"] = "2001:db8::1"
	line := loonWireGuardLine(t, p)
	if !strings.Contains(line, "endpoint=2001:db8::1:51820") {
		t.Errorf("IPv6 endpoint 写法变了(需要真机验证后才能改):\n%s", line)
	}
}

func TestEgernWireGuardZeroOptionalFieldsOmitted(t *testing.T) {
	p := masterWireGuardProxy()
	p["mtu"] = 0
	p["persistent-keepalive"] = 0
	_, fields := egernProxy(t, produceEgern(t, p))
	for _, k := range []string{"mtu", "keepalive"} {
		if v, bad := fields[k]; bad {
			t.Errorf("零值 %s 不应输出,得到 %#v", k, v)
		}
	}

	p = masterWireGuardProxy()
	p["persistent-keepalive"] = 25
	_, fields = egernProxy(t, produceEgern(t, p))
	if fields["keepalive"] != 25 || fields["mtu"] != 1420 {
		t.Errorf("keepalive / mtu 应输出,得到 %#v", fields)
	}
}

// Loon 与 sing-box 共用 allowed-ips 的规整:坏网段丢掉,全坏时回落默认值。
func TestLoonWireGuardMalformedAllowedIPs(t *testing.T) {
	for in, want := range map[string]string{
		"[0.0.0.0/0, ::/0]": `allowed-ips="0.0.0.0/0,::/0",`,
		"['10.0.0.0/8']":    `allowed-ips="10.0.0.0/8",`,
		"garbage":           `allowed-ips="0.0.0.0/0,::/0",`,
	} {
		p := masterWireGuardProxy()
		p["allowed-ips"] = in
		if line := loonWireGuardLine(t, p); !strings.Contains(line, want) {
			t.Errorf("allowed-ips=%q 应输出 %s:\n%s", in, want, line)
		}
	}
}
