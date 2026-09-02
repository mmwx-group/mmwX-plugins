package substore

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func produceEgern(t *testing.T, p Proxy) string {
	t.Helper()
	out, err := NewEgernProducer().Produce([]Proxy{p}, "", nil)
	if err != nil {
		t.Fatalf("produce err: %v", err)
	}
	return out.(string)
}

// egernProxy 把产物**解析回来**再断言,而不是在文本里找子串。
// 断言子串是这个 producer 之前的做法,它有个致命盲区:输出是不是合法 YAML、能不能被
// 客户端读回去,子串断言一个字都测不到 —— 它发了一年多的 JSON-in-YAML,测试全绿。
func egernProxy(t *testing.T, out string) (string, map[string]any) {
	t.Helper()
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("产物不是合法 YAML: %v\n%s", err, out)
	}
	if len(doc.Proxies) != 1 {
		t.Fatalf("期望 1 个节点,得到 %d:\n%s", len(doc.Proxies), out)
	}
	for typ, fields := range doc.Proxies[0] {
		m, ok := fields.(map[string]any)
		if !ok {
			t.Fatalf("节点字段不是映射: %T\n%s", fields, out)
		}
		return typ, m
	}
	t.Fatalf("节点是空的:\n%s", out)
	return "", nil
}

func wantEgern(t *testing.T, out, wantType string, want map[string]any) {
	t.Helper()
	typ, fields := egernProxy(t, out)
	if typ != wantType {
		t.Errorf("type = %q, want %q\n%s", typ, wantType, out)
	}
	for k, wv := range want {
		gv, ok := fields[k]
		if !ok {
			t.Errorf("缺字段 %s:\n%s", k, out)
			continue
		}
		if !reflect.DeepEqual(gv, wv) {
			t.Errorf("字段 %s = %#v, want %#v\n%s", k, gv, wv, out)
		}
	}
}

// Egern 要块状 YAML,不是 JSON-in-YAML;而节点名里的 emoji 必须原样出现。
//
// 用户实报(#504):Egern 的解析器不收 `- {"vless":{...}}`。那种写法在规范上是合法
// YAML(JSON 是 YAML 的子集),但官方文档给的是块状,块状也是所有解析器都认的一侧。
// 顺带钉死 emoji:yaml.Marshal 会把国旗转义成 \U0001F1FA\U0001F1F8,而节点名几乎都带
// 国旗 —— 这正是不能直接用 yaml.Marshal、要自己发射的原因。
func TestEgernEmitsBlockYAMLWithRawEmoji(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "vless", "name": "🇺🇸 美国06 | 1x", "server": "a.example.com",
		"port": 443, "uuid": "uid", "tls": true, "sni": "a.example.com",
	})

	if strings.Contains(out, `{"`) {
		t.Errorf("还在发 JSON-in-YAML:\n%s", out)
	}
	if !strings.Contains(out, "  - vless:\n") {
		t.Errorf("不是块状 YAML(应有 `  - vless:` 起头):\n%s", out)
	}
	if strings.Contains(out, `\U`) || strings.Contains(out, `\u`) {
		t.Errorf("emoji 被转义了:\n%s", out)
	}
	if !strings.Contains(out, "🇺🇸 美国06 | 1x") {
		t.Errorf("节点名没原样出现:\n%s", out)
	}

	_, fields := egernProxy(t, out)
	// 端口要是数字,不能是 "443" 也不能是 443.0。
	if port, ok := fields["port"].(int); !ok || port != 443 {
		t.Errorf("port = %#v, want int 443\n%s", fields["port"], out)
	}
	if name, _ := fields["name"].(string); name != "🇺🇸 美国06 | 1x" {
		t.Errorf("name 读回来是 %q\n%s", name, out)
	}
}

// 会被 YAML 读歪的值必须加引号:纯数字串、true/no 之类的裸词、含 ": " 的串。
func TestEgernQuotesAmbiguousScalars(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "ss", "name": "080", "server": "1.2.3.4", "port": 8388,
		"cipher": "aes-256-gcm", "password": "no",
	})
	_, fields := egernProxy(t, out)
	if name, ok := fields["name"].(string); !ok || name != "080" {
		t.Errorf("纯数字名读回来成了 %#v(该是字符串 \"080\")\n%s", fields["name"], out)
	}
	if pw, ok := fields["password"].(string); !ok || pw != "no" {
		t.Errorf("裸词密码读回来成了 %#v(该是字符串 \"no\")\n%s", fields["password"], out)
	}
}

func TestEgernWireGuard(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "wireguard", "name": "wg1",
		"ip": "10.0.0.2", "ip-cidr": 24, "ipv6": "fd00::2",
		"private-key": "PRIV", "dns": "1.1.1.1, 8.8.8.8", "mtu": 1420,
		"peers": []interface{}{map[string]interface{}{
			"server": "1.2.3.4", "port": 51820,
			"public-key": "PUB", "pre-shared-key": "PSK", "reserved": "1 / 2 / 3",
		}},
	})
	wantEgern(t, out, "wireguard", map[string]any{
		"local_ipv4": "10.0.0.2/24", "local_ipv6": "fd00::2/128",
		"private_key": "PRIV", "peer_public_key": "PUB", "preshared_key": "PSK",
		"reserved":    []any{"1", "2", "3"},
		"dns_servers": []any{"1.1.1.1", "8.8.8.8"},
		"mtu":         1420,
	})
}

func TestEgernSnell(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "snell", "name": "snell1", "server": "1.2.3.4", "port": 443,
		"psk": "mypsk", "version": 4, "udp": true,
		"obfs-opts": map[string]interface{}{"mode": "http", "host": "h.com"},
	})
	wantEgern(t, out, "snell", map[string]any{
		"psk": "mypsk", "version": 4, "udp_relay": true,
		"obfs": "http", "obfs_host": "h.com",
	})

	// snell v2 不应有 udp_relay
	v2 := produceEgern(t, Proxy{"type": "snell", "name": "s2", "server": "x", "port": 1, "psk": "p", "version": 2, "udp": true})
	if _, fields := egernProxy(t, v2); fields["udp_relay"] != nil {
		t.Errorf("snell v2 不该有 udp_relay:\n%s", v2)
	}
	// 非法 version 应被过滤
	bad := produceEgern(t, Proxy{"type": "snell", "name": "s3", "server": "x", "port": 1, "psk": "p", "version": 9})
	if strings.Contains(bad, "s3") {
		t.Errorf("snell 非法 version 应被过滤:\n%s", bad)
	}
}

func TestEgernSSH(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "ssh", "name": "ssh1", "server": "1.2.3.4", "port": 22,
		"username": "root", "password": "pw", "private-key": "KEY", "host-key": []interface{}{"hk1"},
	})
	wantEgern(t, out, "ssh", map[string]any{
		"username": "root", "password": "pw", "private_key": "KEY",
		"host_keys": []any{"hk1"},
	})
}

func TestEgernAnyTLS(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "anytls", "name": "at1", "server": "1.2.3.4", "port": 443,
		"password": "pw", "sni": "a.com", "skip-cert-verify": true,
		"reality-opts": map[string]interface{}{"public-key": "PK", "short-id": "SID"},
	})
	wantEgern(t, out, "anytls", map[string]any{
		"password": "pw", "sni": "a.com", "skip_tls_verify": true,
		"reality": map[string]any{"public_key": "PK", "short_id": "SID"},
	})

	// network 非 tcp 应被过滤
	bad := produceEgern(t, Proxy{"type": "anytls", "name": "atbad", "server": "x", "port": 1, "network": "ws"})
	if strings.Contains(bad, "atbad") {
		t.Errorf("anytls 非 tcp 应被过滤:\n%s", bad)
	}
}

func TestEgernGrpc(t *testing.T) {
	out := produceEgern(t, Proxy{
		"type": "vless", "name": "v1", "server": "1.2.3.4", "port": 443, "uuid": "uid",
		"network": "grpc", "tls": true, "sni": "g.com", "skip-cert-verify": true,
		"grpc-opts": map[string]interface{}{"grpc-service-name": "gsn"},
	})
	// 注意 sni / skip_tls_verify 是嵌在 transport.grpc 里的,不在节点顶层 —— 老测试
	// 按子串断言 `"sni":"g.com"`,匹配到的其实就是这个嵌套位置,读起来却像在顶层。
	wantEgern(t, out, "vless", map[string]any{
		"user_id": "uid",
		"transport": map[string]any{
			"grpc": map[string]any{"service_name": "gsn", "sni": "g.com", "skip_tls_verify": true},
		},
	})

	// multi 模式 gRPC 应被过滤
	bad := produceEgern(t, Proxy{"type": "vmess", "name": "gm", "server": "x", "port": 1, "uuid": "u",
		"network": "grpc", "grpc-opts": map[string]interface{}{"_grpc-type": "multi"}})
	if strings.Contains(bad, "gm") {
		t.Errorf("multi 模式 gRPC 应被过滤:\n%s", bad)
	}
}
