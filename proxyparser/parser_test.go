package proxyparser

import "testing"

// subset 断言 want 的每个键值都出现在 got 中（标量/slice 相等；map 递归）。
func subset(t *testing.T, name string, got map[string]any, want map[string]any) {
	t.Helper()
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("[%s] 缺少字段 %q (got=%v)", name, k, got)
			continue
		}
		switch wvt := wv.(type) {
		case map[string]any:
			gm, ok := gv.(map[string]any)
			if !ok {
				t.Errorf("[%s] 字段 %q 期望 map,实际 %T=%v", name, k, gv, gv)
				continue
			}
			subset(t, name+"."+k, gm, wvt)
		default:
			if !scalarEq(gv, wv) {
				t.Errorf("[%s] 字段 %q = %#v,期望 %#v", name, k, gv, wv)
			}
		}
	}
}

func scalarEq(a, b any) bool {
	if as, ok := a.([]string); ok {
		bs, ok := b.([]string)
		if !ok || len(as) != len(bs) {
			return false
		}
		for i := range as {
			if as[i] != bs[i] {
				return false
			}
		}
		return true
	}
	return a == b
}

// TestParse_Regression 锁定迁移后的基础解析行为(Stage 2:行为不变)。
func TestParse_Regression(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want map[string]any
	}{
		{"shadowsocks", "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#ss-node",
			map[string]any{"type": "ss", "server": "1.2.3.4", "port": 8388, "name": "ss-node"}},
		{"trojan", "trojan://pass@1.2.3.4:443?sni=example.com#trojan-node",
			map[string]any{"type": "trojan", "server": "1.2.3.4", "port": 443, "password": "pass"}},
		{"vless", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp#vless-node",
			map[string]any{"type": "vless", "server": "1.2.3.4", "port": 443}},
	}
	for _, c := range cases {
		got, err := Parse(c.uri)
		if err != nil {
			t.Errorf("[%s] Parse error: %v", c.name, err)
			continue
		}
		subset(t, c.name, got, c.want)
	}
}

// TestParse_Issue98 覆盖 issue #98 的四类 URI，断言修复后字段不丢。
func TestParse_Issue98(t *testing.T) {
	t.Run("vless-reality", func(t *testing.T) {
		got, err := Parse("vless://11111111-2222-3333-4444-555555555555@h.example.com:443?security=reality&sni=x.com&fp=chrome&pbk=PBKEY&sid=&spx=%2Fpath&type=tcp#reality")
		if err != nil {
			t.Fatal(err)
		}
		subset(t, "vless-reality", got, map[string]any{
			"type": "vless", "tls": true, "servername": "x.com",
			"client-fingerprint": "chrome", "skip-cert-verify": true,
			"reality-opts": map[string]any{"public-key": "PBKEY", "short-id": "", "spider-x": "/path"},
		})
	})

	t.Run("hysteria2", func(t *testing.T) {
		got, err := Parse("hysteria2://pa%40ss@h.example.com:443?peer=x.com&insecure=1&obfs=salamander&obfs-password=op&mport=1000-2000&pinSHA256=ABC&hop-interval=30#hy2")
		if err != nil {
			t.Fatal(err)
		}
		subset(t, "hysteria2", got, map[string]any{
			"type": "hysteria2", "password": "pa@ss", "sni": "x.com",
			"skip-cert-verify": true, "obfs": "salamander", "obfs-password": "op",
			"ports": "1000-2000", "tls-fingerprint": "ABC", "hop-interval": 30,
		})
	})

	t.Run("tuic", func(t *testing.T) {
		got, err := Parse("tuic://11111111-2222-3333-4444-555555555555:pass@h.example.com:443?sni=x.com&insecure=1&fast_open=1&disable_sni=1&reduce_rtt=1&udp_over_stream=1#tuic")
		if err != nil {
			t.Fatal(err)
		}
		subset(t, "tuic", got, map[string]any{
			"type": "tuic", "uuid": "11111111-2222-3333-4444-555555555555", "password": "pass",
			"sni": "x.com", "skip-cert-verify": true,
			"fast-open": true, "disable-sni": true, "reduce-rtt": true, "udp-over-stream": true,
			"alpn": []string{"h3"},
		})
	})

	t.Run("naive", func(t *testing.T) {
		got, err := Parse("naive+https://user:pass@h.example.com:443?sni=x.com&uot=1#naive")
		if err != nil {
			t.Fatal(err)
		}
		subset(t, "naive", got, map[string]any{
			"type": "naive", "username": "user", "password": "pass",
			"sni": "x.com", "udp-over-tcp": true,
		})
	})
}

// TestParse_SkipCertAliases 验证 6 种 skip-cert-verify 别名都被识别且输出真 bool。
func TestParse_SkipCertAliases(t *testing.T) {
	aliases := []string{"insecure", "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify", "skipCertVerify"}
	for _, a := range aliases {
		uri := "tuic://uuid:pass@h.example.com:443?sni=x.com&" + a + "=1#n"
		got, err := Parse(uri)
		if err != nil {
			t.Errorf("[%s] error: %v", a, err)
			continue
		}
		v, ok := got["skip-cert-verify"].(bool)
		if !ok {
			t.Errorf("[%s] skip-cert-verify 不是 bool: %T=%v", a, got["skip-cert-verify"], got["skip-cert-verify"])
			continue
		}
		if !v {
			t.Errorf("[%s] skip-cert-verify 应为 true", a)
		}
	}
}

// TestParse_SubStoreBugFixes 验证对照 Sub-Store 修复的 3 个真 bug（下游 substore producer 衔接）。
func TestParse_SubStoreBugFixes(t *testing.T) {
	// 1) WireGuard：无连字符的 presharedkey 应规整为 pre-shared-key（下游只认 pre-shared-key/preshared-key）
	t.Run("wireguard-psk", func(t *testing.T) {
		got, err := Parse("wireguard://cHJpdmF0ZQ@h.example.com:51820?publickey=PUBKEY&presharedkey=PSKKEY&address=10.0.0.2/32#wg")
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := got["pre-shared-key"].(string); v != "PSKKEY" {
			t.Errorf("pre-shared-key = %v, want PSKKEY", got["pre-shared-key"])
		}
		if _, bad := got["presharedkey"]; bad {
			t.Error("不应残留无连字符的 presharedkey")
		}
	})

	// 2) Hysteria2：pinSHA256 应写 tls-fingerprint（下游统一从 tls-fingerprint 读取）
	t.Run("hysteria2-tls-fingerprint", func(t *testing.T) {
		got, err := Parse("hysteria2://pass@h.example.com:443?pinSHA256=ABCDEF#hy2")
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := got["tls-fingerprint"].(string); v != "ABCDEF" {
			t.Errorf("tls-fingerprint = %v, want ABCDEF", got["tls-fingerprint"])
		}
		if _, bad := got["fingerprint"]; bad {
			t.Error("不应写 fingerprint（应为 tls-fingerprint）")
		}
	})

	// 3) ws early-data：独立 ed 参数 → ws-opts.max-early-data + early-data-header-name
	t.Run("ws-early-data", func(t *testing.T) {
		got, err := Parse("vless://11111111-2222-3333-4444-555555555555@h:443?type=ws&path=%2Fpath&ed=2048#n")
		if err != nil {
			t.Fatal(err)
		}
		ws, _ := got["ws-opts"].(map[string]any)
		if ws == nil {
			t.Fatal("缺少 ws-opts")
		}
		if ws["max-early-data"] != 2048 {
			t.Errorf("max-early-data = %v, want 2048", ws["max-early-data"])
		}
		if ws["early-data-header-name"] != "Sec-WebSocket-Protocol" {
			t.Errorf("early-data-header-name = %v, want Sec-WebSocket-Protocol", ws["early-data-header-name"])
		}
	})
}
