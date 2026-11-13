package proxyparser

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

const (
	testHostKeyEd  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIyO6tU0mhlc7rlP+iBz5r4642XOAUuAF7kZqNAc7TpK"
	testHostKeyRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD7aoFC+ymj8NJL/xMqYzRLGp=="
)

func TestParseSSHURL(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want map[string]any
	}{
		{
			name: "完整:编码过的用户名密码、两把公钥、中文名",
			uri:  "ssh://us%40er:p%40ss%3Aw%23rd@1.2.3.4:2222?host-key=ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIIyO6tU0mhlc7rlP%2BiBz5r4642XOAUuAF7kZqNAc7TpK&host-key=ssh-rsa%20AAAAB3NzaC1yc2EAAAADAQABAAABAQD7aoFC%2Bymj8NJL%2FxMqYzRLGp%3D%3D#%E9%A6%99%E6%B8%AF%20SSH",
			want: map[string]any{"name": "香港 SSH", "type": "ssh", "server": "1.2.3.4", "port": 2222, "username": "us@er", "password": "p@ss:w#rd", "udp": false,
				"host-key": []string{testHostKeyEd, testHostKeyRSA}},
		},
		{
			name: "缺省端口 22、没有公钥、没有名称",
			uri:  "ssh://root:pw@example.com",
			want: map[string]any{"name": "SSH Node", "type": "ssh", "server": "example.com", "port": 22, "username": "root", "password": "pw", "udp": false},
		},
		{
			name: "IPv6 + 一个参数里逗号分隔多把 + 手写未编码的 '+'(类型与 base64 之间的空格写成了 +)",
			uri:  "ssh://root:pw@[2001:db8::1]:22?host-key=" + strings.ReplaceAll(testHostKeyEd, " ", "+") + "," + strings.ReplaceAll(testHostKeyRSA, " ", "%20") + "#n",
			want: map[string]any{"name": "n", "type": "ssh", "server": "2001:db8::1", "port": 22, "username": "root", "password": "pw", "udp": false,
				"host-key": []string{testHostKeyEd, testHostKeyRSA}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.uri)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got  %#v\nwant %#v", got, c.want)
			}
		})
	}

	for _, bad := range []string{
		"ssh://1.2.3.4:22",            // 没有用户名
		"ssh://root@1.2.3.4:22",       // 没有密码(只支持密码认证)
		"ssh://root:pw@1.2.3.4:99999", // 端口越界
		"ssh://root:pw@:22",           // 没有服务器
	} {
		if n, err := Parse(bad); err == nil {
			t.Fatalf("%s 应该解析失败,得到 %#v", bad, n)
		}
	}
}

func TestParseSurgeLineSSH(t *testing.T) {
	line := `HK SSH = ssh, 1.2.3.4, 22, username=root, password="p,w=1", idle-timeout=180, server-fingerprint = "` + testHostKeyEd + `,` + testHostKeyRSA + `"`
	got := parseSurgeLine(line)
	want := map[string]any{"name": "HK SSH", "type": "ssh", "server": "1.2.3.4", "port": 22, "username": "root", "password": "p,w=1", "udp": false,
		"host-key": []string{testHostKeyEd, testHostKeyRSA}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}

	// 引用钥匙串私钥的行:单行拿不到私钥,跳过而不是生成一个连不上的节点。
	if n := parseSurgeLine(`K = ssh, 1.2.3.4, 22, username=root, private-key=key1`); n != nil {
		t.Fatalf("private-key 行应跳过,得到 %#v", n)
	}
	// snell 行的解析不受影响。
	if n := parseSurgeLine(`S = snell, 1.2.3.4, 443, psk=abc, version=4`); n == nil || n["psk"] != "abc" {
		t.Fatalf("snell 行解析回归: %#v", n)
	}
	// 订阅里混着 URI 与 Surge 行时两种都能认出来。
	nodes, err := ParseSubscription("ssh://root:pw@1.2.3.4:22#a\n" + line)
	if err != nil || len(nodes) != 2 || nodes[0]["type"] != "ssh" || nodes[1]["type"] != "ssh" {
		t.Fatalf("ParseSubscription: %v %#v", err, nodes)
	}
}

// 面板生成的 mihomo ssh 节点(host-key 是列表)→ URI → 再解析,字段要完全还原。
func TestSSHURIRoundTrip(t *testing.T) {
	node := map[string]any{"name": "[AgentB] ssh-12325 #1", "type": "ssh", "server": "2001:db8::2", "port": 12325,
		"username": "kt user", "password": "a+b/c=d&e#f%g", "udp": false,
		"host-key": []any{testHostKeyEd, testHostKeyRSA}}
	uri, err := substore.NewURIProducer().ProduceOne(node)
	if err != nil || !strings.HasPrefix(uri, "ssh://") {
		t.Fatalf("encode: %q %v", uri, err)
	}
	back, err := Parse(uri)
	if err != nil {
		t.Fatalf("Parse(%s): %v", uri, err)
	}
	node["host-key"] = []string{testHostKeyEd, testHostKeyRSA}
	if !reflect.DeepEqual(back, node) {
		t.Fatalf("往返不一致\nuri  %s\ngot  %#v\nwant %#v", uri, back, node)
	}

	// 没有密码(私钥认证)的节点不输出链接。
	if out, _ := substore.NewURIProducer().ProduceOne(map[string]any{"name": "k", "type": "ssh", "server": "1.2.3.4", "port": 22, "username": "root", "private-key": "x"}); out != "" {
		t.Fatalf("私钥节点不该输出链接: %q", out)
	}
}

// Surge 输出:mihomo 的 host-key 列表 → server-fingerprint="a,b";再用 Surge 行解析读回来一致。
func TestSurgeSSHServerFingerprint(t *testing.T) {
	node := map[string]any{"name": "HK", "type": "ssh", "server": "1.2.3.4", "port": 22, "username": "root", "password": "pw",
		"host-key": []any{testHostKeyEd, testHostKeyRSA}}
	out, err := substore.GetDefaultFactory().GetProducer("surge")
	if err != nil {
		t.Fatal(err)
	}
	res, err := out.Produce([]substore.Proxy{node}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := res.(string)
	want := `server-fingerprint="` + testHostKeyEd + `,` + testHostKeyRSA + `"`
	if !strings.Contains(text, want) {
		t.Fatalf("Surge 输出缺少公钥校验:\n%s", text)
	}
	var line string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "=ssh,") {
			line = l
		}
	}
	back := parseSurgeLine(line)
	if back == nil || !reflect.DeepEqual(back["host-key"], []string{testHostKeyEd, testHostKeyRSA}) || back["password"] != "pw" {
		t.Fatalf("Surge 行读回不一致: %q → %#v", line, back)
	}

	// 已有 server-fingerprint(Sub-Store 来的节点)时照旧用它,不重复输出。
	node2 := map[string]any{"name": "X", "type": "ssh", "server": "1.2.3.4", "port": 22, "username": "root", "password": "pw",
		"server-fingerprint": testHostKeyEd, "host-key": []any{testHostKeyRSA}}
	res2, _ := out.Produce([]substore.Proxy{node2}, "", nil)
	if s, _ := res2.(string); strings.Count(s, "server-fingerprint") != 1 || !strings.Contains(s, testHostKeyEd) {
		t.Fatalf("server-fingerprint 优先: %s", s)
	}
}
