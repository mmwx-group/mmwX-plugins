package proxyparser

import (
	"encoding/base64"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

// #885 原样:2022 PSK 是标准 base64(含 '+' '/' '='),导出工具把 '=' 或 '/' 或 ':' 转义了、
// '+' 留着字面量。以前只要 userinfo 里有 '%' 就整段 QueryUnescape,'+' 变空格,
// agent 建出站时 base64 解码报 illegal base64 data。
func TestParseSS2022Ticket885Sample(t *testing.T) {
	const k1, k2 = "Ab+cDef/GhIjKlMnOpQrSw==", "Zy+xWvU/tSrQpOnMlKjIhg=="
	cases := []struct{ name, userinfo string }{
		{"padding-%3D", "2022-blake3-aes-128-gcm:Ab+cDef/GhIjKlMnOpQrSw%3D%3D:Zy+xWvU/tSrQpOnMlKjIhg%3D%3D"},
		{"slash-%2F", "2022-blake3-aes-128-gcm:Ab+cDef%2FGhIjKlMnOpQrSw==:Zy+xWvU%2FtSrQpOnMlKjIhg=="},
		{"separator-%3A", "2022-blake3-aes-128-gcm:Ab+cDef/GhIjKlMnOpQrSw==%3AZy+xWvU/tSrQpOnMlKjIhg=="},
		{"all-escaped", "2022-blake3-aes-128-gcm%3AAb%2BcDef%2FGhIjKlMnOpQrSw%3D%3D%3AZy%2BxWvU%2FtSrQpOnMlKjIhg%3D%3D"},
		{"no-escape", "2022-blake3-aes-128-gcm:Ab+cDef/GhIjKlMnOpQrSw==:Zy+xWvU/tSrQpOnMlKjIhg=="},
	}
	for _, c := range cases {
		node, err := Parse("ss://" + c.userinfo + "@1.2.3.4:8388#ss2022")
		if err != nil {
			t.Errorf("[%s] 解析失败: %v", c.name, err)
			continue
		}
		if node["cipher"] != "2022-blake3-aes-128-gcm" {
			t.Errorf("[%s] cipher = %v", c.name, node["cipher"])
		}
		pw, _ := node["password"].(string)
		if pw != k1+":"+k2 {
			t.Errorf("[%s] password = %q,期望 %q", c.name, pw, k1+":"+k2)
			continue
		}
		// agent(sing-shadowsocks)就是按 ':' 拆段逐段 StdEncoding 解码的
		for _, seg := range strings.Split(pw, ":") {
			raw, err := base64.StdEncoding.DecodeString(seg)
			if err != nil || len(raw) != 16 {
				t.Errorf("[%s] PSK 段 %q 解码失败: len=%d err=%v", c.name, seg, len(raw), err)
			}
		}
	}
}

// 标准 base64 userinfo 自带 '+',外部工具把填充 '=' 写成 %3D 时整条导入报错。
func TestParseSSBase64UserinfoWithEscapedPadding(t *testing.T) {
	cases := []struct{ method, password string }{
		{"aes-256-gcm", "x~>y>"},
		{"aes-256-gcm", "pa~ss>w"},
	}
	for _, c := range cases {
		b64 := base64.StdEncoding.EncodeToString([]byte(c.method + ":" + c.password))
		if !strings.Contains(b64, "+") || !strings.HasSuffix(b64, "=") {
			t.Fatalf("测试数据应同时含 '+' 和填充: %s", b64)
		}
		userinfo := strings.ReplaceAll(b64, "=", "%3D")
		node, err := Parse("ss://" + userinfo + "@1.2.3.4:8388#ss")
		if err != nil {
			t.Errorf("[%s] 解析失败: %v", c.password, err)
			continue
		}
		if node["cipher"] != c.method || node["password"] != c.password {
			t.Errorf("[%s] cipher=%v password=%q,期望 %q", c.password, node["cipher"], node["password"], c.password)
		}
	}
}

// 各协议密码含 + / = % : @ 时,主控导出(复制链接 / URI 订阅)再导入必须逐字节一致。
func TestCredentialURIExportImportRoundTrip(t *testing.T) {
	fixed := []string{
		"pa+ss", "a+b/c=d%e:f@g", "p%41ss", "%2B%2F", "+++", "==", "100%", "p@ss:w/rd", "@", ":", "/", "%",
		// '?' '>' '~' 和非 ASCII 才会让 socks 导出的 base64 里出现 '+' '/'
		"ab?de>", "q?r>s~t", "密码+/=%:@",
	}
	rng := rand.New(rand.NewPCG(885, 2026))
	const alphabet = "aBf09+/=%:@"
	randPW := func() string {
		b := make([]byte, 1+rng.IntN(24))
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(b)
	}
	passwords := append([]string{}, fixed...)
	for range 300 {
		passwords = append(passwords, randPW())
	}

	type spec struct {
		name   string
		proxy  func(pw string) substore.Proxy
		fields []string // 必须逐字节还原的字段
	}
	const user = "us+er"
	specs := []spec{
		{"ss2022", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "ss", "name": "n", "server": "s.example.com", "port": 8388,
				"cipher": "2022-blake3-aes-256-gcm", "password": pw}
		}, []string{"cipher", "password"}},
		{"ss-base64", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "ss", "name": "n", "server": "s.example.com", "port": 8388,
				"cipher": "aes-256-gcm", "password": pw}
		}, []string{"cipher", "password"}},
		{"hysteria2", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "hysteria2", "name": "n", "server": "s.example.com", "port": 443,
				"password": pw, "obfs": "salamander", "obfs-password": pw}
		}, []string{"password", "obfs-password"}},
		{"tuic", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "tuic", "name": "n", "server": "s.example.com", "port": 443,
				"uuid": "11111111-2222-3333-4444-555555555555", "password": pw}
		}, []string{"uuid", "password"}},
		{"socks", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "socks5", "name": "n", "server": "s.example.com", "port": 1080,
				"username": user, "password": pw}
		}, []string{"username", "password"}},
		{"http", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "http", "name": "n", "server": "s.example.com", "port": 8080,
				"username": user, "password": pw}
		}, []string{"username", "password"}},
		{"naive", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "naive", "name": "n", "server": "s.example.com", "port": 443,
				"username": user, "password": pw}
		}, []string{"username", "password"}},
		{"mieru", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "mieru", "name": "n", "server": "s.example.com", "port": 2999,
				"username": user, "password": pw, "transport": "TCP"}
		}, []string{"username", "password"}},
		{"anytls", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "anytls", "name": "n", "server": "s.example.com", "port": 443,
				"password": pw}
		}, []string{"password"}},
		{"trojan", func(pw string) substore.Proxy {
			return substore.Proxy{"type": "trojan", "name": "n", "server": "s.example.com", "port": 443,
				"password": pw}
		}, []string{"password"}},
	}

	producer := substore.NewURIProducer()
	for _, sp := range specs {
		failures := 0
		socksSawEscapedSlash := false
		for _, pw := range passwords {
			proxy := sp.proxy(pw)
			uri, err := producer.ProduceOne(proxy)
			if err != nil || uri == "" {
				t.Fatalf("[%s] 导出失败 pw=%q: %v (%q)", sp.name, pw, err, uri)
			}
			if sp.name == "socks" && strings.Contains(uri, "%2F") {
				socksSawEscapedSlash = true
			}
			node, err := Parse(uri)
			if err != nil {
				t.Errorf("[%s] 导入失败 pw=%q uri=%s: %v", sp.name, pw, uri, err)
				failures++
			} else {
				for _, f := range sp.fields {
					if got, _ := node[f].(string); got != proxy[f] {
						t.Errorf("[%s] %s 往返不一致: got %q,原值 %q (uri=%s)", sp.name, f, got, proxy[f], uri)
						failures++
					}
				}
			}
			if failures >= 5 {
				break
			}
		}
		// socks 导出的是 PathEscape(base64),base64 里的 '/' 会写成 %2F —— 确认这条路径真的被覆盖到
		if sp.name == "socks" && !socksSawEscapedSlash {
			t.Errorf("[socks] 用例没有覆盖到 base64 含 '/'(%%2F)的情况")
		}
	}
}

// 随机 2022 PSK(16/32 字节,1-2 段)导出再导入必须不变:以前 PSK 同时含 '+' 和 '/' 时必坏。
func TestSS2022RandomPSKRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(885, 1))
	producer := substore.NewURIProducer()
	for i := range 2000 {
		keyLen, cipher := 16, "2022-blake3-aes-128-gcm"
		if i%2 == 1 {
			keyLen, cipher = 32, "2022-blake3-aes-256-gcm"
		}
		segs := make([]string, 1+i%3/2)
		for j := range segs {
			raw := make([]byte, keyLen)
			for k := range raw {
				raw[k] = byte(rng.IntN(256))
			}
			segs[j] = base64.StdEncoding.EncodeToString(raw)
		}
		psk := strings.Join(segs, ":")
		uri, err := producer.ProduceOne(substore.Proxy{"type": "ss", "name": "n", "server": "1.2.3.4",
			"port": 8388, "cipher": cipher, "password": psk})
		if err != nil {
			t.Fatal(err)
		}
		node, err := Parse(uri)
		if err != nil {
			t.Fatalf("导入失败 %s: %v", uri, err)
		}
		if node["password"] != psk {
			t.Fatalf("PSK 往返不一致: got %q,原值 %q (uri=%s)", node["password"], psk, uri)
		}
	}
}

// 很多实例会长期停在 proxyparser ≤v0.2.7(userinfo 按 QueryUnescape 解),还会互相导入对方的
// 「复制链接」。导出端把 '+' 写成 %2B,旧导入端才能拿回原密码。
func TestUserInfoExportSurvivesFormDecodingImporter(t *testing.T) {
	const psk = "Ab+cDef/GhIjKlMnOpQrSw==:Zy+xWvU/tSrQpOnMlKjIhg=="
	producer := substore.NewURIProducer()
	cases := []struct {
		name, want string
		proxy      substore.Proxy
	}{
		{"ss2022", "2022-blake3-aes-128-gcm:" + psk, substore.Proxy{"type": "ss", "name": "n",
			"server": "1.2.3.4", "port": 8388, "cipher": "2022-blake3-aes-128-gcm", "password": psk}},
		{"hysteria2", "pa+ss/w=rd", substore.Proxy{"type": "hysteria2", "name": "n",
			"server": "1.2.3.4", "port": 443, "password": "pa+ss/w=rd"}},
	}
	for _, c := range cases {
		uri, err := producer.ProduceOne(c.proxy)
		if err != nil {
			t.Fatal(err)
		}
		rest := uri[strings.Index(uri, "://")+3:]
		userinfo := rest[:strings.LastIndex(rest, "@")]
		got, err := url.QueryUnescape(userinfo)
		if err != nil || got != c.want {
			t.Errorf("[%s] 旧导入端(QueryUnescape)读到 %q,期望 %q (uri=%s, err=%v)", c.name, got, c.want, uri, err)
		}
	}
}

// 别家工具导出的链接:userinfo 里字面 '+' 不能变空格;trojan / anytls 的 %XX 要解出来。
func TestCredentialKeepsPlusAllSchemes(t *testing.T) {
	cases := []struct {
		name, uri string
		want      map[string]any
	}{
		{"hysteria2", "hysteria2://pa+ss%2F@h.example.com:443?obfs=salamander&obfs-password=o%2Bp%3D#h",
			map[string]any{"password": "pa+ss/", "obfs-password": "o+p="}},
		{"hysteria", "hysteria://pa+ss@h.example.com:443?obfs=xplus#h",
			map[string]any{"password": "pa+ss"}},
		{"tuic-userinfo", "tuic://11111111-2222-3333-4444-555555555555:pa+ss%40@h.example.com:443#t",
			map[string]any{"password": "pa+ss@"}},
		{"socks5-plain", "socks5://us+er:pa+ss%3A@h.example.com:1080#s",
			map[string]any{"username": "us+er", "password": "pa+ss:"}},
		{"http", "http://us+er:pa+ss%25@h.example.com:8080#h",
			map[string]any{"username": "us+er", "password": "pa+ss%"}},
		{"naive", "naive+https://us+er:pa+ss%2F@h.example.com:443#n",
			map[string]any{"username": "us+er", "password": "pa+ss/"}},
		{"mieru", "mieru://us+er:pa+ss%2F@h.example.com:2999?transport=TCP#m",
			map[string]any{"username": "us+er", "password": "pa+ss/"}},
		{"trojan", "trojan://p%40ss+x@h.example.com:443?sni=h.example.com#t",
			map[string]any{"password": "p@ss+x"}},
		{"anytls", "anytls://p%40ss+x@h.example.com:443?sni=h.example.com#a",
			map[string]any{"password": "p@ss+x"}},
	}
	for _, c := range cases {
		node, err := Parse(c.uri)
		if err != nil {
			t.Errorf("[%s] 解析失败: %v", c.name, err)
			continue
		}
		subset(t, c.name, node, c.want)
	}
}

// query 与 userinfo 不同,是表单编码:3x-ui(url.Values / URLSearchParams)、hysteria2 官方、
// PHP 面板都把空格写成 '+'、'+' 写成 %2B。密码类参数(obfs-password / tuic ?password= /
// obfsParam)和 path 一样按表单解,否则带空格的密码导进来是 '+',握手失败。
func TestQueryParamsFormDecoded(t *testing.T) {
	const obfsPW, tuicPW = "my obfs+1/=", "p w+x"
	q := url.Values{}
	q.Set("obfs", "salamander")
	q.Set("obfs-password", obfsPW)
	hy2 := "hysteria2://auth@1.2.3.4:443?" + q.Encode() + "#x"
	if !strings.Contains(hy2, "my+obfs%2B1") {
		t.Fatalf("测试前提:url.Values 应把空格编成 '+'、'+' 编成 %%2B: %s", hy2)
	}
	tq := url.Values{}
	tq.Set("password", tuicPW)
	tuic := "tuic://11111111-2222-3333-4444-555555555555@h.example.com:443?" + tq.Encode() + "#t"

	cases := []struct {
		name, uri string
		want      map[string]any
	}{
		{"hy2-url.Values", hy2, map[string]any{"obfs-password": obfsPW}},
		{"tuic-url.Values", tuic, map[string]any{"password": tuicPW}},
		{"hysteria-obfsParam", "hysteria://pw@h.example.com:443?obfs=xplus&obfsParam=o+p%2B#h",
			map[string]any{"obfs-password": "o p+"}},
	}
	for _, c := range cases {
		node, err := Parse(c.uri)
		if err != nil {
			t.Errorf("[%s] 解析失败: %v", c.name, err)
			continue
		}
		subset(t, c.name, node, c.want)
	}

	node, err := Parse("trojan://pw@h.example.com:443?type=ws&path=%2Fa+b#t")
	if err != nil {
		t.Fatal(err)
	}
	ws, _ := node["ws-opts"].(map[string]any)
	if ws == nil || ws["path"] != "/a b" {
		t.Fatalf("ws path = %v,期望 %q", ws, "/a b")
	}
}

// trojan 的导入端都不按表单解码,'+' 导出时保持字面量:≤v0.2.7(原样读密码)导入
// base64 风格的密码也不会读到 "%2B"。'%' '/' '@' 等照样转义。
func TestTrojanExportKeepsPlusLiteral(t *testing.T) {
	producer := substore.NewURIProducer()
	cases := []struct{ password, userinfo string }{
		{"p+ss", "p+ss"},
		{"Ab+cDef+==", "Ab+cDef+=="},
		{"Ab+cD/e==", "Ab+cD%2Fe=="},
		{"p%41@x", "p%2541%40x"},
	}
	for _, c := range cases {
		uri, err := producer.ProduceOne(substore.Proxy{"type": "trojan", "name": "t",
			"server": "h.example.com", "port": 443, "password": c.password})
		if err != nil {
			t.Fatal(err)
		}
		rest := strings.TrimPrefix(uri, "trojan://")
		if got := rest[:strings.LastIndex(rest, "@")]; got != c.userinfo {
			t.Errorf("[%s] 导出 userinfo = %q,期望 %q (uri=%s)", c.password, got, c.userinfo, uri)
		}
		node, err := Parse(uri)
		if err != nil || node["password"] != c.password {
			t.Errorf("[%s] 导回来是 %v (err=%v, uri=%s)", c.password, node["password"], err, uri)
		}
	}
}

// ss 插件参数整串是 plugin=<encodeURIComponent(...)>,parseQueryParams 已解过一层;
// parseSSPlugin 再解一层时不能把 '+' 当空格,shadow-tls 密码 / obfs-host 才导得回来。
func TestSSPluginOptsKeepPlus(t *testing.T) {
	producer := substore.NewURIProducer()
	cases := []struct {
		name  string
		proxy substore.Proxy
		want  map[string]any
	}{
		{"shadow-tls", substore.Proxy{"type": "ss", "name": "s", "server": "h.example.com", "port": 8388,
			"cipher": "aes-128-gcm", "password": "pw", "plugin": "shadow-tls",
			"plugin-opts": map[string]any{"host": "ex.com", "password": "Ab+cD/e==", "version": 3}},
			map[string]any{"host": "ex.com", "password": "Ab+cD/e==", "version": 3}},
		{"obfs", substore.Proxy{"type": "ss", "name": "s", "server": "h.example.com", "port": 8388,
			"cipher": "aes-128-gcm", "password": "pw", "plugin": "obfs",
			"plugin-opts": map[string]any{"mode": "http", "host": "a+b.example.com"}},
			map[string]any{"mode": "http", "host": "a+b.example.com"}},
	}
	for _, c := range cases {
		uri, err := producer.ProduceOne(c.proxy)
		if err != nil {
			t.Fatal(err)
		}
		node, err := Parse(uri)
		if err != nil {
			t.Fatalf("[%s] 导入失败 %s: %v", c.name, uri, err)
		}
		opts, _ := node["plugin-opts"].(map[string]any)
		for k, v := range c.want {
			if opts[k] != v {
				t.Errorf("[%s] plugin-opts.%s = %#v,期望 %#v (uri=%s)", c.name, k, opts[k], v, uri)
			}
		}
	}
}

// SS2022 单端口多用户的密码是「服务器PSK:用户PSK」。从前导出成 method:服务器PSK:用户PSK,
// userinfo 里两个冒号,按冒号切的导入端各取各的:Loon 只留服务器 PSK,sing-box 侧的转换只留用户 PSK,
// 节点都连不上。密码里的 ':' 必须编成 %3A,userinfo 只留 method 后面那一个冒号。
func TestSS2022MultiUserExportEscapesPasswordColon(t *testing.T) {
	const psk = "5V73ImiDfE+FJGOU7q1JSQ==:QUJDREVGR0hJSktMTU5PUA=="
	uri, err := substore.NewURIProducer().ProduceOne(substore.Proxy{"type": "ss", "name": "PO0 HK",
		"server": "1.2.3.4", "port": 443, "cipher": "2022-blake3-aes-128-gcm", "password": psk})
	if err != nil {
		t.Fatal(err)
	}
	userinfo := strings.TrimPrefix(uri, "ss://")
	userinfo = userinfo[:strings.LastIndex(userinfo, "@")]
	parts := strings.Split(userinfo, ":")
	if len(parts) != 2 {
		t.Fatalf("userinfo 应只有 method 后一个冒号,实得 %d 段: %s", len(parts), userinfo)
	}
	// 按冒号切的导入端:取第二段(也是最后一段)再做百分号解码,必须拿回完整的两段 PSK
	got, err := url.PathUnescape(parts[1])
	if err != nil || got != psk {
		t.Fatalf("按冒号切再解码 = %q (err=%v), want %q", got, err, psk)
	}
	if node, err := Parse(uri); err != nil || node["password"] != psk {
		t.Fatalf("自家导入端读回 = %v (err=%v), want %q", node["password"], err, psk)
	}
}
