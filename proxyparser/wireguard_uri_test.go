package proxyparser

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

// wgKey 造一把 32 字节的 WG 密钥,保证 base64 里同时有 '+' '/' '='。
// 真实随机密钥约一半含 '+',这正是以前导入时被变成空格的那一半。
func wgKey(t *testing.T, fill byte) string {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	raw[0], raw[1], raw[2] = 0xfb, 0xef, 0xbe // "++++"
	raw[3], raw[4], raw[5] = 0xff, 0xff, 0xff // "////"
	key := base64.StdEncoding.EncodeToString(raw)
	if !strings.Contains(key, "+") || !strings.Contains(key, "/") || !strings.HasSuffix(key, "=") {
		t.Fatalf("测试密钥应同时含 + / =,得到 %s", key)
	}
	return key
}

func exportWireGuardURI(t *testing.T, proxy substore.Proxy) string {
	t.Helper()
	uri, err := substore.NewURIProducer().ProduceOne(proxy)
	if err != nil || uri == "" {
		t.Fatalf("导出 wireguard:// 失败: %v (%q)", err, uri)
	}
	return uri
}

// 主控导出的 URI(复制节点 / URI 管理)再导入,密钥与地址必须逐字节一致。
func TestWireGuardURIExportImportRoundTrip(t *testing.T) {
	priv, pub, psk := wgKey(t, 1), wgKey(t, 60), wgKey(t, 120)

	cases := []struct {
		name  string
		proxy substore.Proxy
	}{
		{"dual-stack", substore.Proxy{
			"name": "WG 香港 01", "type": "wireguard", "server": "1.2.3.4", "port": 51820,
			"udp": true, "mtu": 1420, "private-key": priv, "public-key": pub,
			"ip": "10.66.0.5", "ipv6": "fd00:66::5",
		}},
		{"v4-only-explicit-allowed-ips", substore.Proxy{
			"name": "wg-v4", "type": "wireguard", "server": "wg.example.com", "port": 443,
			"udp": true, "private-key": priv, "public-key": pub, "pre-shared-key": psk,
			"ip": "10.66.0.6", "allowed-ips": []string{"0.0.0.0/0"},
		}},
		{"ipv6-server-with-lists", substore.Proxy{
			"name": "wg-v6", "type": "wireguard", "server": "2001:db8::1", "port": 51821,
			"udp": true, "mtu": 1280, "private-key": priv, "public-key": pub,
			"ip": "10.66.0.7", "ipv6": "fd00:66::7",
			"allowed-ips": []string{"0.0.0.0/0", "::/0"}, "reserved": []int{1, 2, 3},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri := exportWireGuardURI(t, tc.proxy)
			got, err := Parse(uri)
			if err != nil {
				t.Fatalf("导回失败: %v\n%s", err, uri)
			}
			for k, want := range tc.proxy {
				if !reflect.DeepEqual(got[k], want) {
					t.Errorf("%s: 导出再导入后 = %#v, want %#v\nURI: %s", k, got[k], want, uri)
				}
			}
		})
	}
}

// 第三方生成的 URI 常常不转义 '+'(publickey=Zz+y/x=)或把密钥原样放进 userinfo。
func TestWireGuardURIKeepsLiteralPlusInKeys(t *testing.T) {
	got, err := Parse("wireguard://aB+cD/eF+gH=@1.2.3.4:51820?publickey=Zz+y/x=&presharedkey=Pp+q%2Fr%3D&address=10.0.0.2/32#n")
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"private-key":    "aB+cD/eF+gH=",
		"public-key":     "Zz+y/x=",
		"pre-shared-key": "Pp+q/r=",
	} {
		if got[k] != want {
			t.Errorf("%s = %#v, want %q", k, got[k], want)
		}
	}
}

func TestWireGuardURIIPv6Host(t *testing.T) {
	cases := []struct {
		uri        string
		wantServer string
		wantPort   int
	}{
		{"wireguard://k@[2001:db8::1]:51820/?publickey=P#n", "2001:db8::1", 51820},
		{"wireguard://k@[2001:db8::1]/?publickey=P#n", "2001:db8::1", 51820},
		{"wireguard://k@[2001:db8::1]:443?publickey=P#n", "2001:db8::1", 443},
		// 没加方括号也没写端口:以前被拆成 server="2001:db8:"、port=1
		{"wireguard://k@2001:db8::1/?publickey=P#n", "2001:db8::1", 51820},
		{"wireguard://k@2001:db8::1:51820/?publickey=P#n", "2001:db8::1", 51820},
		{"wireguard://k@1.2.3.4:1234?publickey=P#n", "1.2.3.4", 1234},
		{"wireguard://k@wg.example.com?publickey=P#n", "wg.example.com", 51820},
	}
	for _, tc := range cases {
		got, err := Parse(tc.uri)
		if err != nil {
			t.Fatalf("%s: %v", tc.uri, err)
		}
		if got["server"] != tc.wantServer || got["port"] != tc.wantPort {
			t.Errorf("%s: server/port = %#v/%#v, want %s/%d", tc.uri, got["server"], got["port"], tc.wantServer, tc.wantPort)
		}
	}
}

// 导入节点带着一堆认不出的参数(keepalive / dns / 自定义键),转 sing-box 时不能透传成未知字段。
func TestWireGuardImportedURIToSingboxHasNoUnknownFields(t *testing.T) {
	node, err := Parse("wireguard://" + "cHJpdit/a2V5PQ%3D%3D" + "@5.6.7.8:51820/?publickey=cHViK2tleT0%3D" +
		"&address=10.0.0.2/32&keepalive=25&dns=1.1.1.1,8.8.8.8&foo_bar=x&remote-dns-resolve=1&flag=JP#imported")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := substore.NewSingboxProducer().Produce([]substore.Proxy{node}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Endpoints []map[string]interface{} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(raw.(string)), &cfg); err != nil || len(cfg.Endpoints) != 1 {
		t.Fatalf("期望 1 个 endpoint: %v\n%s", err, raw)
	}
	ep := cfg.Endpoints[0]
	for _, bad := range []string{"keepalive", "persistent_keepalive", "dns", "foo_bar", "foo-bar", "remote_dns_resolve", "flag", "udp", "server"} {
		if _, ok := ep[bad]; ok {
			t.Errorf("endpoint 不应出现 %q(sing-box 会整份拒载)\n%s", bad, raw)
		}
	}
	if ep["private_key"] != "cHJpdit/a2V5PQ==" {
		t.Errorf("private_key = %#v", ep["private_key"])
	}
	peers, _ := ep["peers"].([]interface{})
	if len(peers) != 1 {
		t.Fatalf("期望 1 个 peer\n%s", raw)
	}
	peer, _ := peers[0].(map[string]interface{})
	if peer["public_key"] != "cHViK2tleT0=" || peer["persistent_keepalive_interval"] != float64(25) {
		t.Errorf("peer = %#v", peer)
	}
}

// 名字与 dns 也要能原样导回:名字片段以前按 QueryUnescape 解码('+' 变空格),
// dns 列表导回来是一个逗号串(mihomo 的 dns 是 []string,标量会被拒)。
func TestWireGuardURIRoundTripNameAndDNS(t *testing.T) {
	priv, pub := wgKey(t, 1), wgKey(t, 60)
	for _, dns := range []interface{}{
		[]interface{}{"1.1.1.1", "8.8.8.8"}, // YAML 读回来的形态
		[]string{"1.1.1.1", "8.8.8.8"},      // Go 里直接构造的形态
	} {
		proxy := substore.Proxy{
			"name": "WG+HK 01", "type": "wireguard", "server": "1.2.3.4", "port": 51820,
			"udp": true, "private-key": priv, "public-key": pub, "ip": "10.66.0.5", "dns": dns,
		}
		uri := exportWireGuardURI(t, proxy)
		// '+' 也要转义:按表单解码的导入端(旧版本的本解析器等)否则会把它当空格
		if !strings.HasSuffix(uri, "#WG%2BHK%2001") {
			t.Errorf("名字片段应为 WG%%2BHK%%2001,得到 %s", uri)
		}
		got, err := Parse(uri)
		if err != nil {
			t.Fatalf("导回失败: %v\n%s", err, uri)
		}
		if got["name"] != "WG+HK 01" {
			t.Errorf("name = %#v, want %q\nURI: %s", got["name"], "WG+HK 01", uri)
		}
		if want := []interface{}{"1.1.1.1", "8.8.8.8"}; !reflect.DeepEqual(got["dns"], want) {
			t.Errorf("dns(%T) = %#v, want %#v\nURI: %s", dns, got["dns"], want, uri)
		}
	}
}

// 第三方 URI:名字片段按 decodeURIComponent 语义('+' 是字面量,与上游 Sub-Store 一致);
// v0.2.7 导出的列表是 "[a b]"(%v 格式),也要能拆回列表。
func TestWireGuardURIThirdPartyNameAndLegacyLists(t *testing.T) {
	got, err := Parse("wireguard://k@1.2.3.4:51820?publickey=P&address=10.0.0.2/32" +
		"&dns=%5B1.1.1.1+8.8.8.8%5D&allowed-ips=%5B0.0.0.0%2F0+%3A%3A%2F0%5D#WG+HK%2001")
	if err != nil {
		t.Fatal(err)
	}
	if got["name"] != "WG+HK 01" {
		t.Errorf("name = %#v, want %q", got["name"], "WG+HK 01")
	}
	if want := []interface{}{"1.1.1.1", "8.8.8.8"}; !reflect.DeepEqual(got["dns"], want) {
		t.Errorf("dns = %#v, want %#v", got["dns"], want)
	}
	if want := []string{"0.0.0.0/0", "::/0"}; !reflect.DeepEqual(got["allowed-ips"], want) {
		t.Errorf("allowed-ips = %#v, want %#v", got["allowed-ips"], want)
	}
}

// 导入的 dns 直接(不经 YAML)进各 producer:clash 系输出列表,Loon 只取一个 v4 / 一个 v6。
func TestWireGuardImportedDNSDownstream(t *testing.T) {
	node, err := Parse("wireguard://k@1.2.3.4:51820?publickey=P&address=10.0.0.2/32&dns=1.1.1.1,2606:4700::1111,8.8.8.8#n")
	if err != nil {
		t.Fatal(err)
	}
	out, err := substore.NewClashMetaProducer().Produce([]substore.Proxy{node}, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if list := out.([]substore.Proxy); len(list) != 1 || substore.GetStringSlice(list[0], "dns") == nil {
		t.Errorf("clashmeta 的 dns 应是列表,得到 %#v", list)
	}
	line, err := substore.NewLoonProducer().ProduceOne(node, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, ",dns=1.1.1.1,") || !strings.Contains(line, ",dnsv6=2606:4700::1111") || strings.Contains(line, "8.8.8.8") {
		t.Errorf("Loon 的 dns 应只有一个 v4 + 一个 v6:\n%s", line)
	}
}
