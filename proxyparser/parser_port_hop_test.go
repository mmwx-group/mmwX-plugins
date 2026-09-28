package proxyparser

import "testing"

// TestParse_Issue86_PortHopping 覆盖 authority 中端口范围/列表的端口跳跃写法(#86)。
func TestParse_Issue86_PortHopping(t *testing.T) {
	cases := []struct {
		name   string
		uri    string
		want   map[string]any
		absent []string
	}{
		{"hysteria2-range", "hysteria2://pass@1.2.3.4:20000-30000/?sni=a.com#hy2",
			map[string]any{"type": "hysteria2", "server": "1.2.3.4", "port": 20000, "ports": "20000-30000", "sni": "a.com", "name": "hy2"}, nil},
		{"hy2-list", "hy2://pass@1.2.3.4:443,20000-30000?sni=a.com#hy2",
			map[string]any{"type": "hysteria2", "port": 443, "ports": "443,20000-30000"}, nil},
		{"hysteria2-ipv6-range", "hysteria2://pass@[2001:db8::1]:20000-30000?sni=a.com#v6",
			map[string]any{"server": "2001:db8::1", "port": 20000, "ports": "20000-30000"}, nil},
		{"hysteria-v1-range", "hysteria://pass@1.2.3.4:20000-30000?peer=a.com#hy1",
			map[string]any{"type": "hysteria", "port": 20000, "ports": "20000-30000"}, nil},
		{"mport-query-still-works", "hysteria2://pass@1.2.3.4:443?mport=1000-2000&hop-interval=30#hy2",
			map[string]any{"port": 443, "ports": "1000-2000", "hop-interval": 30}, nil},
		{"ports-query-overrides-authority", "hysteria2://pass@1.2.3.4:20000-30000?ports=40000-50000#hy2",
			map[string]any{"port": 20000, "ports": "40000-50000"}, nil},
		{"single-port-no-ports", "hysteria2://pass@1.2.3.4:443?sni=a.com#hy2",
			map[string]any{"port": 443}, []string{"ports"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.uri)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			subset(t, c.name, got, c.want)
			for _, k := range c.absent {
				if v, ok := got[k]; ok {
					t.Errorf("[%s] 不应包含字段 %q, 实际 %#v", c.name, k, v)
				}
			}
		})
	}
}
