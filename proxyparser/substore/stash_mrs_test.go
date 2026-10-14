package substore

import (
	"strings"
	"testing"
)

// Stash 已支持 mrs 规则集:rule-providers 里的 .mrs 原样下发,不再改写成 .yaml。
func TestStashKeepsMrsRuleProviders(t *testing.T) {
	proxies := []Proxy{{"name": "vl", "type": "vless", "server": "5.6.7.8", "port": 443, "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}
	full := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "PROXY", "type": "select", "proxies": []interface{}{"vl"}},
		},
		"rule-providers": map[string]interface{}{
			"google": map[string]interface{}{
				"type": "http", "behavior": "domain", "format": "mrs",
				"url":  "https://example.com/geosite/google.mrs",
				"path": "./ruleset/google.mrs", "interval": 86400,
			},
		},
		"rules": []interface{}{"RULE-SET,google,PROXY", "MATCH,DIRECT"},
	}
	raw, err := NewStashProducer().Produce(proxies, "", &ProduceOptions{FullConfig: full})
	if err != nil {
		t.Fatal(err)
	}
	out := raw.(string)
	for _, want := range []string{
		"format: mrs",
		"url: https://example.com/geosite/google.mrs",
		"path: ./ruleset/google.mrs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Stash 输出应保留 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "google.yaml") || strings.Contains(out, "format: yaml") {
		t.Errorf("不应再把 mrs 改写成 yaml:\n%s", out)
	}
}
