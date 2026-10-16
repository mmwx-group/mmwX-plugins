package substore

import (
	"reflect"
	"strings"
	"testing"
)

func srConfProduce(t *testing.T, proxies []Proxy, full map[string]interface{}) string {
	t.Helper()
	raw, err := NewShadowrocketTemplateProducer().Produce(proxies, "", &ProduceOptions{FullConfig: full})
	if err != nil {
		t.Fatal(err)
	}
	return raw.(string)
}

// iluobei/miaomiaowuX#4:节点全是模板版不认 / 静默丢掉的类型时,[Proxy] 为空、PROXY 组被剔空,
// 规则里的 PROXY 全变成 DIRECT。现在这些类型都能写出来,PROXY 保留。
func TestShadowrocketConfIssue4KeepsProxy(t *testing.T) {
	proxies := []Proxy{
		{"name": "sn5", "type": "snell", "server": "1.1.1.1", "port": 443, "psk": "k", "version": 5, "udp": true},
		{"name": "at", "type": "anytls", "server": "1.1.1.2", "port": 443, "password": "p", "sni": "a.com"},
		{"name": "hy", "type": "hysteria2", "server": "1.1.1.3", "port": 443, "password": "p"},
		{"name": "mi", "type": "mieru", "server": "1.1.1.4", "port": 443, "username": "u", "password": "p"},
	}
	full := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "PROXY", "type": "select", "proxies": []interface{}{"sn5", "at", "hy", "mi"}},
		},
		"rule-providers": map[string]interface{}{
			"google": map[string]interface{}{"url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt"},
		},
		"rules": []interface{}{"RULE-SET,google,PROXY", "GEOIP,CN,DIRECT", "MATCH,PROXY"},
	}
	out := srConfProduce(t, proxies, full)

	if got := srConfProxyNames(out); !reflect.DeepEqual(got, []string{"sn5", "at", "hy"}) {
		t.Errorf("[Proxy] = %v\n%s", got, out)
	}
	if !strings.Contains(out, "# 已跳过 mieru: mi(") {
		t.Errorf("Mieru 应留注释:\n%s", out)
	}
	if got := srConfGroups(out)["PROXY"]; !reflect.DeepEqual(got, []string{"sn5", "at", "hy"}) {
		t.Errorf("PROXY = %v\n%s", got, out)
	}
	wantRules := []string{
		"RULE-SET,https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt,PROXY",
		"GEOIP,CN,DIRECT",
		"FINAL,PROXY",
	}
	if got := confSection(out, "[Rule]"); !reflect.DeepEqual(got, wantRules) {
		t.Errorf("规则 = %q\nwant %q", got, wantRules)
	}
}

// 各协议写成 Shadowrocket 手册里的本地节点语法:节点名称=类型,地址,端口,参数=值
func TestShadowrocketConfProxyLines(t *testing.T) {
	cases := []struct {
		proxy Proxy
		want  string
	}{
		{Proxy{"name": "ss", "type": "ss", "server": "a.com", "port": 8388, "cipher": "aes-128-gcm", "password": "p", "udp": true,
			"plugin": "obfs", "plugin-opts": map[string]interface{}{"mode": "http", "host": "bing.com"}},
			"ss=ss,a.com,8388,method=aes-128-gcm,password=p,obfs=http,obfs-host=bing.com,udp=1"},
		{Proxy{"name": "vm", "type": "vmess", "server": "a.com", "port": 443, "uuid": "id", "alterId": 0, "cipher": "auto",
			"tls": true, "servername": "s.com", "network": "ws",
			"ws-opts": map[string]interface{}{"path": "/ws", "headers": map[string]interface{}{"Host": "h.com"}}},
			"vm=vmess,a.com,443,password=id,method=auto,alterId=0,tls=true,peer=s.com,obfs=websocket,path=/ws,obfsParam=h.com"},
		{Proxy{"name": "rl", "type": "vless", "server": "a.com", "port": 443, "uuid": "id", "tls": true,
			"flow": "xtls-rprx-vision", "servername": "www.apple.com", "client-fingerprint": "chrome",
			"reality-opts": map[string]interface{}{"public-key": "PBK", "short-id": "01"}},
			"rl=vless,a.com,443,password=id,tls=true,peer=www.apple.com,fp=chrome,pbk=PBK,sid=01,xtls=2"},
		{Proxy{"name": "gr", "type": "vless", "server": "a.com", "port": 443, "uuid": "id", "tls": true, "network": "grpc",
			"grpc-opts": map[string]interface{}{"grpc-service-name": "svc"}},
			"gr=vless,a.com,443,password=id,tls=true,obfs=grpc,path=svc"},
		{Proxy{"name": "tj", "type": "trojan", "server": "a.com", "port": 443, "password": "p", "sni": "s.com", "skip-cert-verify": true},
			"tj=trojan,a.com,443,password=p,peer=s.com,allowInsecure=1"},
		{Proxy{"name": "h2", "type": "hysteria2", "server": "a.com", "port": 443, "password": "p", "obfs": "salamander",
			"obfs-password": "op", "sni": "s.com", "alpn": []interface{}{"h3"}},
			"h2=hysteria2,a.com,443,auth=p,obfsParam=op,peer=s.com,alpn=h3,udp=1"},
		{Proxy{"name": "tu", "type": "tuic", "server": "a.com", "port": 443, "uuid": "id", "password": "p", "sni": "s.com"},
			"tu=tuic,a.com,443,password=p,user=id,peer=s.com,udp=1"},
		{Proxy{"name": "sn", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 4,
			"obfs-opts": map[string]interface{}{"mode": "http", "host": "bing.com"}},
			"sn=snell,a.com,443,password=k,version=4,obfs=http,obfs-host=bing.com"},
		{Proxy{"name": "wg", "type": "wireguard", "server": "a.com", "port": 51820, "private-key": "PK", "public-key": "PUB",
			"ip": "10.0.0.2", "mtu": 1280, "reserved": []interface{}{1, 2, 3}, "dns": []interface{}{"1.1.1.1", "8.8.8.8"}},
			"wg=wireguard,a.com,51820,privateKey=PK,publicKey=PUB,ip=10.0.0.2,udp=1,dns=1.1.1.1,mtu=1280,reserved=1/2/3"},
		{Proxy{"name": "hp", "type": "http", "server": "a.com", "port": 8080, "username": "u", "password": "p", "tls": true},
			"hp=https,a.com,8080,u,p"},
		{Proxy{"name": "s5", "type": "socks5", "server": "a.com", "port": 1080, "username": "u", "password": "p", "udp": true},
			"s5=socks5,a.com,1080,u,p,udp=1"},
	}
	for _, c := range cases {
		out := srConfProduce(t, []Proxy{c.proxy}, map[string]interface{}{})
		got := confSection(out, "[Proxy]")
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s:\n got %q\nwant %q", GetString(c.proxy, "name"), got, c.want)
		}
	}
}

// 写不出来的节点留注释、不进组:Snell + ShadowTLS、多 peer WireGuard、缺端口的节点。
func TestShadowrocketConfSkipsWithComment(t *testing.T) {
	out := srConfProduce(t, []Proxy{
		{"name": "stls", "type": "snell", "server": "a.com", "port": 443, "psk": "k", "version": 5,
			"obfs-opts": map[string]interface{}{"mode": "shadow-tls", "host": "h.com", "password": "pw", "version": 3}},
		{"name": "wgm", "type": "wireguard", "server": "a.com", "port": 51820, "private-key": "PK",
			"peers": []interface{}{map[string]interface{}{}, map[string]interface{}{}}},
		{"name": "noport", "type": "trojan", "server": "a.com", "password": "p"},
	}, map[string]interface{}{})
	if got := confSection(out, "[Proxy]"); len(got) != 0 {
		t.Errorf("不应输出节点: %q", got)
	}
	for _, name := range []string{"stls", "wgm", "noport"} {
		if !strings.Contains(out, ": "+name+"(") {
			t.Errorf("%s 应留注释:\n%s", name, out)
		}
	}
}

// include-all 展开成显式成员并按 filter / exclude-filter 筛;filter 用了 Go 正则不认的写法时
// 原样交给 policy-regex-filter;展开后仍为空的组、relay 组整组删除,规则改 DIRECT。
func TestShadowrocketConfExpandsIncludeAll(t *testing.T) {
	proxies := []Proxy{
		{"name": "香港 01", "type": "trojan", "server": "a.com", "port": 443, "password": "p"},
		{"name": "香港 02 IPLC", "type": "trojan", "server": "b.com", "port": 443, "password": "p"},
		{"name": "日本 01", "type": "trojan", "server": "c.com", "port": 443, "password": "p"},
	}
	full := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "PROXY", "type": "select", "proxies": []interface{}{"HK", "DIRECT"}, "include-all": true},
			map[string]interface{}{"name": "HK", "type": "url-test", "include-all": true, "filter": "香港|HK",
				"exclude-filter": "IPLC", "timeout": 3000, "interval": 300},
			map[string]interface{}{"name": "LOOK", "type": "select", "include-all": true, "filter": "(?=.*日本).*"},
			map[string]interface{}{"name": "US", "type": "select", "include-all": true, "filter": "美国"},
			map[string]interface{}{"name": "CHAIN", "type": "relay", "proxies": []interface{}{"香港 01", "日本 01"}},
		},
		"rules": []interface{}{"DOMAIN,us.com,US", "DOMAIN,c.com,CHAIN", "DOMAIN,j.com,LOOK", "MATCH,PROXY"},
	}
	out := srConfProduce(t, proxies, full)

	groups := srConfGroups(out)
	want := map[string][]string{
		"PROXY": {"HK", "DIRECT", "香港 01", "香港 02 IPLC", "日本 01"},
		"HK":    {"香港 01"},
		"LOOK":  {},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("组 = %v\nwant %v\n%s", groups, want, out)
	}
	lines := strings.Join(confSection(out, "[Proxy Group]"), "\n")
	for _, s := range []string{"LOOK = select,policy-regex-filter=(?=.*日本).*", "interval=300,timeout=3"} {
		if !strings.Contains(lines, s) {
			t.Errorf("缺少 %q:\n%s", s, lines)
		}
	}
	wantRules := []string{"DOMAIN,us.com,DIRECT", "DOMAIN,c.com,DIRECT", "DOMAIN,j.com,LOOK", "FINAL,PROXY"}
	if got := confSection(out, "[Rule]"); !reflect.DeepEqual(got, wantRules) {
		t.Errorf("规则 = %q\nwant %q", got, wantRules)
	}
}
