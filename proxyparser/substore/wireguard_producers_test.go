package substore

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// 主控下发的逐用户 WG 节点长这样:模板 {name,type,server,port,udp,mtu} + 凭据
// {private-key, public-key(服务端公钥), ip, ipv6}。没有 keepalive / psk / allowed-ips。
func masterWireGuardProxy() Proxy {
	return Proxy{
		"name": "wg-in", "type": "wireguard", "server": "1.2.3.4", "port": 51820,
		"udp": true, "mtu": 1420,
		"private-key": "cHJpdmF0ZStrZXkvd2l0aD1zeW1ib2xzKysrKysrKys=",
		"public-key":  "c2VydmVyK3B1Yi9rZXk9PT09PT09PT09PT09PT09PT0=",
		"ip":          "10.66.0.5", "ipv6": "fd00:66::5",
	}
}

// 下面两张表照抄 sing-box 源码(/Users/luobei/Workspace/opensource/sing-box,v1.14.0-alpha.39):
// option/endpoint.go(type/tag)、option/wireguard.go WireGuardEndpointOptions / WireGuardPeer、
// option/outbound.go DialerOptions 的 json tag(`json:"-"` 的不算)。
// 官方 sing-box 遇到不在表里的字段会整份配置拒载。
var singboxStrictWGEndpointFields = map[string]bool{
	"type": true, "tag": true,
	"system": true, "name": true, "mtu": true, "address": true, "private_key": true,
	"listen_port": true, "peers": true, "udp_timeout": true, "udp_mapping": true,
	"udp_filtering": true, "udp_nat_max": true, "workers": true,
	"detour": true, "bind_interface": true, "inet4_bind_address": true, "inet6_bind_address": true,
	"bind_address_no_port": true, "protect_path": true, "routing_mark": true, "reuse_addr": true,
	"netns": true, "connect_timeout": true, "tcp_fast_open": true, "tcp_multi_path": true,
	"disable_tcp_keep_alive": true, "tcp_keep_alive": true, "tcp_keep_alive_interval": true,
	"udp_fragment": true, "domain_resolver": true, "network_strategy": true, "network_type": true,
	"fallback_network_type": true, "fallback_delay": true, "domain_strategy": true,
}

var singboxStrictWGPeerFields = map[string]bool{
	"address": true, "port": true, "public_key": true, "pre_shared_key": true,
	"allowed_ips": true, "persistent_keepalive_interval": true, "reserved": true,
}

// singboxWGEndpoint 跑一遍 sing-box producer(与主控相同的 outputType=""),
// 按 JSON 解析回来,断言只有一个 WG endpoint 且所有字段都在 sing-box 的严格字段表里。
func singboxWGEndpoint(t *testing.T, proxy Proxy) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	raw, err := NewSingboxProducer().Produce([]Proxy{proxy}, "", nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	var cfg struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
		Endpoints []map[string]interface{} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(raw.(string)), &cfg); err != nil {
		t.Fatalf("产物不是合法 JSON: %v\n%s", err, raw)
	}
	if len(cfg.Outbounds) != 0 || len(cfg.Endpoints) != 1 {
		t.Fatalf("期望 0 个 outbound、1 个 endpoint,得到 %d / %d\n%s", len(cfg.Outbounds), len(cfg.Endpoints), raw)
	}
	ep := cfg.Endpoints[0]
	for k := range ep {
		if !singboxStrictWGEndpointFields[k] {
			t.Errorf("endpoint 出现 sing-box 不认识的字段 %q(整份配置会被拒载)\n%s", k, raw)
		}
	}
	peers, _ := ep["peers"].([]interface{})
	if len(peers) != 1 {
		t.Fatalf("期望 1 个 peer,得到 %d\n%s", len(peers), raw)
	}
	peer, _ := peers[0].(map[string]interface{})
	for k := range peer {
		if !singboxStrictWGPeerFields[k] {
			t.Errorf("peer 出现 sing-box 不认识的字段 %q\n%s", k, raw)
		}
	}
	return ep, peer
}

func wantField(t *testing.T, where string, m map[string]interface{}, key string, want interface{}) {
	t.Helper()
	if got := m[key]; !reflect.DeepEqual(got, want) {
		t.Errorf("%s.%s = %#v, want %#v", where, key, got, want)
	}
}

func TestSingboxWireGuardMasterNodeStrictFields(t *testing.T) {
	ep, peer := singboxWGEndpoint(t, masterWireGuardProxy())

	wantField(t, "endpoint", ep, "type", "wireguard")
	wantField(t, "endpoint", ep, "tag", "wg-in")
	wantField(t, "endpoint", ep, "private_key", "cHJpdmF0ZStrZXkvd2l0aD1zeW1ib2xzKysrKysrKys=")
	wantField(t, "endpoint", ep, "mtu", float64(1420))
	wantField(t, "endpoint", ep, "address", []interface{}{"10.66.0.5/32", "fd00:66::5/128"})
	if _, bad := ep["persistent_keepalive"]; bad {
		t.Error("endpoint 不应出现 persistent_keepalive(sing-box 没有这个字段)")
	}

	wantField(t, "peer", peer, "address", "1.2.3.4")
	wantField(t, "peer", peer, "port", float64(51820))
	wantField(t, "peer", peer, "public_key", "c2VydmVyK3B1Yi9rZXk9PT09PT09PT09PT09PT09PT0=")
	wantField(t, "peer", peer, "allowed_ips", []interface{}{"0.0.0.0/0", "::/0"})
	for _, k := range []string{"persistent_keepalive_interval", "pre_shared_key", "reserved"} {
		if _, bad := peer[k]; bad {
			t.Errorf("没配 %s 时不应输出", k)
		}
	}
}

// 只有 v4 的服务器:主控不写 ipv6,并显式写 allowed-ips: [0.0.0.0/0]。
func TestSingboxWireGuardV4OnlyAllowedIPs(t *testing.T) {
	proxy := masterWireGuardProxy()
	delete(proxy, "ipv6")
	proxy["allowed-ips"] = []interface{}{"0.0.0.0/0"}
	ep, peer := singboxWGEndpoint(t, proxy)
	wantField(t, "endpoint", ep, "address", []interface{}{"10.66.0.5/32"})
	wantField(t, "peer", peer, "allowed_ips", []interface{}{"0.0.0.0/0"})

	// 顶层 allowed-ips 是用户显式配的分流网段,也不能被默认值盖掉
	proxy = masterWireGuardProxy()
	proxy["allowed-ips"] = []interface{}{"10.0.0.0/8"}
	_, peer = singboxWGEndpoint(t, proxy)
	wantField(t, "peer", peer, "allowed_ips", []interface{}{"10.0.0.0/8"})
}

func TestSingboxWireGuardKeepaliveGoesToPeer(t *testing.T) {
	for _, key := range []string{"persistent-keepalive", "keepalive"} {
		proxy := masterWireGuardProxy()
		proxy[key] = 25
		ep, peer := singboxWGEndpoint(t, proxy)
		wantField(t, "peer("+key+")", peer, "persistent_keepalive_interval", float64(25))
		for k := range ep {
			if strings.Contains(k, "keepalive") {
				t.Errorf("%s 不应落到 endpoint 顶层,得到字段 %q", key, k)
			}
		}
	}
}

// URI 导入的外部节点:parseWireGuardURL 把认不出的参数原样(字符串)塞进 proxy。
// 以前 passthroughExtraFields 会把它们改名透传,sing-box 整份拒载。
func TestSingboxWireGuardImportedNodeUnknownParams(t *testing.T) {
	imported := Proxy{
		"type": "wireguard", "name": "imported", "server": "5.6.7.8", "port": 51820,
		"private-key": "UFJJVitrZXkvPT0=", "udp": true,
		"public-key": "UFVCK2tleS89PQ==", "ip": "10.0.0.2", "mtu": 1280,
		"pre-shared-key":     "UFNLK2tleS89PQ==",
		"allowed-ips":        "0.0.0.0/0,::/0",
		"keepalive":          "25",
		"dns":                "1.1.1.1,8.8.8.8",
		"remote-dns-resolve": "1",
		"foo-bar":            "x",
		"flag":               "🇯🇵",
		"_private":           "internal",
	}
	ep, peer := singboxWGEndpoint(t, imported)
	wantField(t, "endpoint", ep, "tag", "imported")
	wantField(t, "endpoint", ep, "address", []interface{}{"10.0.0.2/32"})
	wantField(t, "peer", peer, "persistent_keepalive_interval", float64(25))
	wantField(t, "peer", peer, "pre_shared_key", "UFNLK2tleS89PQ==")
	wantField(t, "peer", peer, "allowed_ips", []interface{}{"0.0.0.0/0", "::/0"})
}

// 非 WG 出站仍然走透传,不能被 WG 的白名单误伤。
func TestSingboxNonWireGuardStillPassthrough(t *testing.T) {
	out, err := NewSingboxProducer().Produce([]Proxy{{
		"name": "vm", "type": "vmess", "server": "1.2.3.4", "port": 443,
		"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "alterId": 0, "cipher": "auto",
		"routing-mark": 255,
	}}, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	list := out.([]map[string]interface{})
	if len(list) != 1 || list[0]["routing_mark"] != 255 {
		t.Errorf("vmess 的 routing-mark 应继续透传成 routing_mark,得到 %#v", list)
	}
}

// B2:clash 系 producer 的 WG 可选字段只在非零 / 非空时输出。
func TestClashFamilyWireGuardOptionalFieldsOnlyWhenSet(t *testing.T) {
	type producer struct {
		name string
		run  func(Proxy) Proxy
	}
	internal := func(p Producer) func(Proxy) Proxy {
		return func(proxy Proxy) Proxy {
			out, err := p.Produce([]Proxy{proxy}, "internal", &ProduceOptions{})
			if err != nil {
				t.Fatalf("%s produce: %v", p.GetType(), err)
			}
			list, _ := out.([]Proxy)
			if len(list) != 1 {
				t.Fatalf("%s: 期望 1 个节点,得到 %d", p.GetType(), len(list))
			}
			return list[0]
		}
	}
	producers := []producer{
		{"clash", internal(NewClashProducer())},
		{"clashmeta", internal(NewClashMetaProducer())},
		{"stash", internal(NewStashProducer())},
		{"shadowrocket", internal(NewShadowrocketProducer())},
		{"shadowrocket-template", internal(NewShadowrocketTemplateProducer())},
	}
	optional := []string{"keepalive", "persistent-keepalive", "preshared-key", "pre-shared-key"}

	for _, pr := range producers {
		got := pr.run(masterWireGuardProxy())
		for _, k := range optional {
			if v, bad := got[k]; bad {
				t.Errorf("%s: 没配时不应输出 %s(得到 %#v)", pr.name, k, v)
			}
		}

		withZero := masterWireGuardProxy()
		withZero["persistent-keepalive"] = 0
		withZero["pre-shared-key"] = ""
		got = pr.run(withZero)
		for _, k := range optional {
			if v, bad := got[k]; bad {
				t.Errorf("%s: 零值 / 空串不应输出 %s(得到 %#v)", pr.name, k, v)
			}
		}

		set := masterWireGuardProxy()
		set["persistent-keepalive"] = 25
		set["pre-shared-key"] = "PSK+/="
		got = pr.run(set)
		for _, k := range []string{"keepalive", "persistent-keepalive"} {
			if GetInt(got, k) != 25 {
				t.Errorf("%s: %s = %#v, want 25", pr.name, k, got[k])
			}
		}
		for _, k := range []string{"preshared-key", "pre-shared-key"} {
			if GetString(got, k) != "PSK+/=" {
				t.Errorf("%s: %s = %#v, want PSK+/=", pr.name, k, got[k])
			}
		}

		// Stash 的写法是 keepalive / preshared-key
		stashStyle := masterWireGuardProxy()
		stashStyle["keepalive"] = 30
		stashStyle["preshared-key"] = "S"
		got = pr.run(stashStyle)
		if GetInt(got, "persistent-keepalive") != 30 || GetString(got, "pre-shared-key") != "S" {
			t.Errorf("%s: keepalive/preshared-key 写法应同步到另一个别名,得到 %#v", pr.name, got)
		}
	}
}

// B2 也覆盖 URI producer:零值 mtu / keepalive 与全 0 的 reserved 不写进 wireguard://。
func TestURIWireGuardOmitsZeroOptionalFields(t *testing.T) {
	p := masterWireGuardProxy()
	p["mtu"] = 0
	p["persistent-keepalive"] = 0
	p["keepalive"] = "0"
	p["reserved"] = []interface{}{0, 0, 0}
	for _, producer := range []Producer{NewURIProducer(), NewV2RayProducer()} {
		out, err := producer.Produce([]Proxy{p}, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		uri := out.(string)
		if producer.GetType() == "v2ray" {
			raw, err := base64.StdEncoding.DecodeString(uri)
			if err != nil {
				t.Fatal(err)
			}
			uri = string(raw)
		}
		for _, bad := range []string{"mtu=", "keepalive=", "reserved="} {
			if strings.Contains(uri, bad) {
				t.Errorf("%s: 零值不应输出 %q:\n%s", producer.GetType(), bad, uri)
			}
		}
	}

	p = masterWireGuardProxy()
	p["persistent-keepalive"] = 25
	p["reserved"] = []int{1, 2, 3}
	uri, err := NewURIProducer().ProduceOne(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mtu=1420", "persistent-keepalive=25", "reserved=1%2C2%2C3"} {
		if !strings.Contains(uri, want) {
			t.Errorf("非零值应照常输出 %q:\n%s", want, uri)
		}
	}
}
