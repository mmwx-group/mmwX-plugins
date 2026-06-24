package substore

import (
	"strings"
	"testing"
)

func TestExpandNameserverPolicy(t *testing.T) {
	p := NewStashProducer()

	tests := []struct {
		name     string
		input    map[string]interface{}
		wantKeys []string
	}{
		{
			name: "comma-separated geosite",
			input: map[string]interface{}{
				"geosite:cn,private": []interface{}{"https://doh.pub/dns-query"},
			},
			wantKeys: []string{"geosite:cn", "geosite:private"},
		},
		{
			name: "comma-separated with spaces",
			input: map[string]interface{}{
				"geosite:cn, private": []interface{}{"https://doh.pub/dns-query"},
			},
			wantKeys: []string{"geosite:cn", "geosite:private"},
		},
		{
			name: "single geosite passthrough",
			input: map[string]interface{}{
				"geosite:geolocation-!cn": []interface{}{"https://dns.google/dns-query"},
			},
			wantKeys: []string{"geosite:geolocation-!cn"},
		},
		{
			name: "domain key passthrough",
			input: map[string]interface{}{
				"+.google.com": []interface{}{"8.8.8.8"},
			},
			wantKeys: []string{"+.google.com"},
		},
		{
			name: "mixed keys",
			input: map[string]interface{}{
				"geosite:cn,private":      []interface{}{"https://doh.pub/dns-query"},
				"geosite:geolocation-!cn": []interface{}{"https://dns.google/dns-query"},
			},
			wantKeys: []string{"geosite:cn", "geosite:private", "geosite:geolocation-!cn"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.expandNameserverPolicy(tt.input)
			if len(result) != len(tt.wantKeys) {
				t.Errorf("got %d keys, want %d", len(result), len(tt.wantKeys))
			}
			for _, key := range tt.wantKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("missing expected key %q", key)
				}
			}
		})
	}
}

func TestExpandNameserverPolicy_ValuesPreserved(t *testing.T) {
	p := NewStashProducer()

	servers := []interface{}{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"}
	input := map[string]interface{}{
		"geosite:cn,private": servers,
	}

	result := p.expandNameserverPolicy(input)

	for _, key := range []string{"geosite:cn", "geosite:private"} {
		val, ok := result[key].([]interface{})
		if !ok {
			t.Fatalf("key %q: expected []interface{}, got %T", key, result[key])
		}
		if len(val) != 2 {
			t.Errorf("key %q: got %d servers, want 2", key, len(val))
		}
	}
}

func TestStashGenerateFullConfig_NameserverPolicy(t *testing.T) {
	p := NewStashProducer()

	proxies := []Proxy{
		{"name": "test", "type": "ss", "server": "1.2.3.4", "port": 443, "cipher": "aes-256-gcm", "password": "pass"},
	}
	opts := &ProduceOptions{
		FullConfig: map[string]interface{}{
			"proxy-groups": []interface{}{},
			"rules":        []interface{}{},
			"dns": map[string]interface{}{
				"nameserver-policy": map[string]interface{}{
					"geosite:cn,private": []interface{}{
						"https://doh.pub/dns-query",
						"https://dns.alidns.com/dns-query",
					},
					"geosite:geolocation-!cn": []interface{}{
						"https://dns.google/dns-query",
					},
				},
			},
		},
	}

	result, err := p.Produce(proxies, "full", opts)
	if err != nil {
		t.Fatal(err)
	}

	output, ok := result.(string)
	if !ok {
		t.Fatal("expected string output")
	}

	// Should have expanded keys, not the original comma-separated one
	if strings.Contains(output, "geosite:cn,private") {
		t.Error("output still contains comma-separated key 'geosite:cn,private'")
	}
	if !strings.Contains(output, "geosite:cn:") {
		t.Error("missing expanded key 'geosite:cn'")
	}
	if !strings.Contains(output, "geosite:private:") {
		t.Error("missing expanded key 'geosite:private'")
	}
	if !strings.Contains(output, "geosite:geolocation-!cn:") {
		t.Error("missing key 'geosite:geolocation-!cn'")
	}
	if !strings.Contains(output, "nameserver-policy:") {
		t.Error("missing nameserver-policy section")
	}
}

func TestStashMergeNameservers(t *testing.T) {
	p := NewStashProducer()

	proxies := []Proxy{
		{"name": "test", "type": "ss", "server": "1.2.3.4", "port": 443, "cipher": "aes-256-gcm", "password": "pass"},
	}
	opts := &ProduceOptions{
		FullConfig: map[string]interface{}{
			"proxy-groups": []interface{}{},
			"rules":        []interface{}{},
			"dns": map[string]interface{}{
				"nameserver": []interface{}{
					"tls://8.8.8.8",
				},
				"direct-nameserver": []interface{}{
					"https://doh.pub/dns-query",
				},
				"proxy-server-nameserver": []interface{}{
					"https://doh.pub/dns-query",
					"tls://1.1.1.1",
				},
			},
		},
	}

	result, err := p.Produce(proxies, "full", opts)
	if err != nil {
		t.Fatal(err)
	}

	output := result.(string)

	// Original nameserver should be present
	if !strings.Contains(output, "tls://8.8.8.8") {
		t.Error("missing original nameserver tls://8.8.8.8")
	}
	// direct-nameserver value should be merged in
	if !strings.Contains(output, "https://doh.pub/dns-query") {
		t.Error("missing merged direct-nameserver value")
	}
	// proxy-server-nameserver unique value should be merged in
	if !strings.Contains(output, "tls://1.1.1.1") {
		t.Error("missing merged proxy-server-nameserver value tls://1.1.1.1")
	}
	// duplicate (doh.pub) should appear only once in nameserver section
	nameserverSection := output[strings.Index(output, "  nameserver:"):]
	nameserverSection = nameserverSection[:strings.Index(nameserverSection, "\n  skip-cert-verify")]
	count := strings.Count(nameserverSection, "https://doh.pub/dns-query")
	if count != 1 {
		t.Errorf("doh.pub appears %d times in nameserver section, want 1", count)
	}
}
