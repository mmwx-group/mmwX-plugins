package substore

import (
	"strings"
	"testing"
)

func TestBuildCompleteLoonConfig(t *testing.T) {
	clashConfig := &ClashConfig{
		ProxyGroups: []ClashProxyGroup{
			{
				Name:      "Proxy",
				Type:      "select",
				Proxies:   []string{"Auto", "DIRECT", "节点A"},
				URL:       "http://www.gstatic.com/generate_204",
				Interval:  300,
			},
			{
				Name:      "Auto",
				Type:      "url-test",
				Proxies:   []string{"节点A", "节点B"},
				URL:       "http://www.gstatic.com/generate_204",
				Interval:  300,
				Tolerance: 100,
			},
		},
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,Proxy",
			"DOMAIN-KEYWORD,github,Proxy",
			"RULE-SET,reject,REJECT",
			"IP-CIDR,192.168.0.0/16,DIRECT",
			"GEOIP,CN,DIRECT",
			"MATCH,Proxy",
		},
		RuleProviders: map[string]ClashRuleProvider{
			"reject": {
				Type:     "http",
				Behavior: "domain",
				URL:      "https://example.com/reject.txt",
				Interval: 86400,
			},
		},
	}

	proxies := []Proxy{
		{
			"name":   "节点A",
			"type":   "ss",
			"server": "1.2.3.4",
			"port":   443,
			"cipher": "aes-256-gcm",
			"password": "test123",
		},
		{
			"name":     "节点B",
			"type":     "trojan",
			"server":   "5.6.7.8",
			"port":     443,
			"password": "trojanpass",
		},
	}

	result, err := BuildCompleteLoonConfig(clashConfig, proxies)
	if err != nil {
		t.Fatalf("BuildCompleteLoonConfig failed: %v", err)
	}

	// Verify sections exist
	if !strings.Contains(result, "[General]") {
		t.Error("missing [General] section")
	}
	if !strings.Contains(result, "[Proxy]") {
		t.Error("missing [Proxy] section")
	}
	if !strings.Contains(result, "[Proxy Group]") {
		t.Error("missing [Proxy Group] section")
	}
	if !strings.Contains(result, "[Rule]") {
		t.Error("missing [Rule] section")
	}

	// Verify proxy group format
	if !strings.Contains(result, "Proxy = select") {
		t.Error("missing select proxy group")
	}
	if !strings.Contains(result, "Auto = url-test") {
		t.Error("missing url-test proxy group")
	}
	if !strings.Contains(result, "tolerance = 100") {
		t.Error("missing tolerance in url-test group")
	}

	// Verify MATCH -> FINAL conversion
	if !strings.Contains(result, "FINAL,Proxy") {
		t.Error("MATCH should be converted to FINAL")
	}
	if strings.Contains(result, "MATCH,Proxy") {
		t.Error("MATCH should not remain in output")
	}

	// Verify rules
	if !strings.Contains(result, "DOMAIN-SUFFIX,google.com,Proxy") {
		t.Error("missing domain rule")
	}
	if !strings.Contains(result, "GEOIP,CN,DIRECT") {
		t.Error("missing GEOIP rule")
	}

	// Verify remote rules from rule-providers
	if !strings.Contains(result, "[Remote Rule]") {
		t.Error("missing [Remote Rule] section")
	}
	if !strings.Contains(result, "https://example.com/reject.txt") {
		t.Error("missing remote rule URL")
	}
}

func TestBuildLoonProxyGroupsWithRegex(t *testing.T) {
	groups := []ClashProxyGroup{
		{
			Name:    "HK",
			Type:    "url-test",
			Proxies: []string{"(香港|HK)"},
			URL:     "http://www.gstatic.com/generate_204",
			Interval: 300,
		},
		{
			Name:    "Manual",
			Type:    "select",
			Proxies: []string{"DIRECT", "(日本|JP)"},
		},
	}

	result := buildLoonProxyGroups(groups)

	if !strings.Contains(result, "NameRegexFilter") {
		t.Error("regex proxies should use NameRegexFilter")
	}
	if !strings.Contains(result, "(香港|HK)") {
		t.Error("regex filter should be preserved")
	}
}

func TestBuildLoonKeleeConfig(t *testing.T) {
	proxies := []Proxy{
		{
			"name":     "HK-SS",
			"type":     "ss",
			"server":   "1.2.3.4",
			"port":     443,
			"cipher":   "aes-256-gcm",
			"password": "test123",
		},
		{
			"name":     "JP-Trojan",
			"type":     "trojan",
			"server":   "5.6.7.8",
			"port":     443,
			"password": "trojanpass",
		},
	}

	result, err := BuildLoonKeleeConfig(proxies)
	if err != nil {
		t.Fatalf("BuildLoonKeleeConfig failed: %v", err)
	}

	// Template sections should be present
	if !strings.Contains(result, "[General]") {
		t.Error("missing [General] section")
	}
	if !strings.Contains(result, "[Remote Filter]") {
		t.Error("missing [Remote Filter] section")
	}
	if !strings.Contains(result, "[Proxy Group]") {
		t.Error("missing [Proxy Group] section")
	}
	if !strings.Contains(result, "[Plugin]") {
		t.Error("missing [Plugin] section")
	}

	// Proxies should be inserted
	if !strings.Contains(result, "HK-SS") {
		t.Error("proxy HK-SS not found in output")
	}
	if !strings.Contains(result, "JP-Trojan") {
		t.Error("proxy JP-Trojan not found in output")
	}

	// Template content should be preserved
	if !strings.Contains(result, "香港节点=NameRegex") {
		t.Error("template Remote Filter should be preserved")
	}
	if !strings.Contains(result, "兜底后备策略=fallback") {
		t.Error("template Proxy Group should be preserved")
	}
}
