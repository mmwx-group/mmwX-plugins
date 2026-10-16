package substore

import (
	"reflect"
	"strings"
	"testing"
)

// confSection 取 INI 风格配置里某一段的非注释行。
func confSection(conf, header string) []string {
	var lines []string
	in := false
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			in = trimmed == header
			continue
		}
		if in && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

var confBuiltinPolicies = map[string]bool{
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "REJECT-TINYGIF": true, "REJECT-NO-DROP": true,
}

// assertNoDanglingPolicies 通用校验:没有空组,组成员与规则目标都指向存在的策略
// (输出了的节点、输出了的组、内置策略)。
func assertNoDanglingPolicies(t *testing.T, conf string, proxyNames []string, groups map[string][]string, rules []string) {
	t.Helper()
	valid := make(map[string]bool)
	for k := range confBuiltinPolicies {
		valid[k] = true
	}
	for _, n := range proxyNames {
		valid[n] = true
	}
	for g := range groups {
		valid[g] = true
	}
	for g, members := range groups {
		if len(members) == 0 {
			t.Errorf("组 %s 是空组:\n%s", g, conf)
		}
		for _, m := range members {
			if !valid[m] {
				t.Errorf("组 %s 引用了不存在的策略 %q:\n%s", g, m, conf)
			}
		}
	}
	for _, r := range rules {
		parts := splitRuleTopLevel(r)
		idx := 2
		if up := strings.ToUpper(parts[0]); up == "FINAL" || up == "MATCH" {
			idx = 1
		}
		if len(parts) > idx && !valid[strings.TrimSpace(parts[idx])] {
			t.Errorf("规则 %q 指向不存在的策略:\n%s", r, conf)
		}
	}
}

func surgePruneFixture() (*ClashConfig, []Proxy) {
	cfg := &ClashConfig{
		ProxyGroups: []ClashProxyGroup{
			{Name: "PROXY", Type: "select", Proxies: []string{"wg-in", "tj"}},
			{Name: "OUTER", Type: "select", Proxies: []string{"ONLYWG"}}, // 级联:ONLYWG 删了它也空了(排在前面,要多轮)
			{Name: "ONLYWG", Type: "select", Proxies: []string{"wg-in"}},
			{Name: "MIX", Type: "select", Proxies: []string{"ONLYWG", "DIRECT"}}, // 剩 DIRECT,保留
			{Name: "VLG", Type: "url-test", Proxies: []string{"vless-node"}},     // 通用:Surge 不支持 VLESS
			{Name: "EMPTY", Type: "select"},                                      // 原本就空:保持原样
			{Name: "CHAIN", Type: "select", Proxies: []string{"land", "land-ok"}},
		},
		Rules: []string{
			"DOMAIN-SUFFIX,c.com,PROXY",
			"DOMAIN,a.com,wg-in",
			"IP-CIDR,1.1.1.0/24,OUTER,no-resolve",
			"AND,((DOMAIN,x.com),(DST-PORT,443)),VLG",
			"GEOIP,CN,DIRECT",
			"MATCH,ONLYWG",
		},
	}
	trojan := func(name string) Proxy {
		return Proxy{"name": name, "type": "trojan", "server": "1.2.3.4", "port": 443, "password": "pw"}
	}
	land := trojan("land")
	land["underlying-proxy"] = "wg-in"
	landOK := trojan("land-ok")
	landOK["underlying-proxy"] = "tj"
	proxies := []Proxy{
		masterWireGuardProxy(),
		trojan("tj"),
		{"name": "vless-node", "type": "vless", "server": "5.6.7.8", "port": 443, "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		land,
		landOK,
	}
	return cfg, proxies
}

// 规格用例 {PROXY:[wg,vl], ONLYWG:[wg], FINAL,ONLYWG} 的 Surge 版(Surge 没有 VLESS,用 trojan 代替 vl),
// 外加级联、underlying-proxy、逻辑规则、原本就空的组。
func TestBuildCompleteSurgeConfigPrunesDanglingPolicies(t *testing.T) {
	cfg, proxies := surgePruneFixture()
	out, err := BuildCompleteSurgeConfig(cfg, proxies, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"wg-in", "vless-node", "ONLYWG", "OUTER", "VLG"} {
		if strings.Contains(out, bad) {
			t.Errorf("输出里不应再有 %q:\n%s", bad, out)
		}
	}

	var proxyNames []string
	for _, line := range confSection(out, "[Proxy]") {
		name := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		proxyNames = append(proxyNames, name)
		if name == "land" && strings.Contains(line, "underlying-proxy") {
			t.Errorf("land 的前置节点没输出,应去掉 underlying-proxy: %s", line)
		}
		if name == "land-ok" && !strings.Contains(line, ",underlying-proxy=tj") {
			t.Errorf("land-ok 的前置节点还在,underlying-proxy 不应被去掉: %s", line)
		}
	}
	groups := make(map[string][]string)
	for _, line := range confSection(out, "[Proxy Group]") {
		kv := strings.SplitN(line, "=", 2)
		fields := strings.Split(kv[1], ",")
		var members []string
		for _, f := range fields[1:] {
			if f = strings.TrimSpace(f); !strings.Contains(f, "=") {
				members = append(members, f)
			}
		}
		groups[strings.TrimSpace(kv[0])] = members
	}
	wantGroups := map[string][]string{
		"PROXY": {"tj"}, "MIX": {"DIRECT"}, "EMPTY": {"DIRECT"}, "CHAIN": {"land", "land-ok"},
	}
	if !reflect.DeepEqual(groups, wantGroups) {
		t.Errorf("组 = %v, want %v\n%s", groups, wantGroups, out)
	}

	rules := confSection(out, "[Rule]")
	wantRules := []string{
		"DOMAIN-SUFFIX,c.com,PROXY",
		"DOMAIN,a.com,DIRECT",
		"IP-CIDR,1.1.1.0/24,DIRECT,no-resolve",
		"AND,((DOMAIN,x.com),(DST-PORT,443)),DIRECT",
		"GEOIP,CN,DIRECT",
		"FINAL,DIRECT",
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Errorf("规则 = %q\nwant %q", rules, wantRules)
	}
	assertNoDanglingPolicies(t, out, proxyNames, groups, rules)

	// 不改调用方的配置
	if got := cfg.ProxyGroups[0].Proxies; !reflect.DeepEqual(got, []string{"wg-in", "tj"}) {
		t.Errorf("调用方的 ProxyGroups 被改了: %v", got)
	}
}

// 没有节点被丢时,输出与剔除前完全一样。
func TestBuildCompleteSurgeConfigUnchangedWithoutDrops(t *testing.T) {
	cfg := &ClashConfig{
		ProxyGroups: []ClashProxyGroup{{Name: "PROXY", Type: "select", Proxies: []string{"tj", "UNKNOWN-POLICY"}}},
		Rules:       []string{"DOMAIN,a.com,UNKNOWN-POLICY", "MATCH,PROXY"},
	}
	proxies := []Proxy{{"name": "tj", "type": "trojan", "server": "1.2.3.4", "port": 443, "password": "pw"}}
	out, err := BuildCompleteSurgeConfig(cfg, proxies, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// 不认识的名字不是「已知但没输出」,原样保留(不误伤别处定义的策略)
	for _, want := range []string{"PROXY = select, tj, UNKNOWN-POLICY", "DOMAIN,a.com,UNKNOWN-POLICY", "FINAL,PROXY"} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少 %q:\n%s", want, out)
		}
	}
}

func shadowrocketPruneFixture() ([]Proxy, map[string]interface{}) {
	proxies := []Proxy{
		{"name": "mi", "type": "mieru", "server": "1.2.3.4", "port": 2999, "username": "u", "password": "p", "transport": "TCP"},
		{"name": "vl", "type": "vless", "server": "5.6.7.8", "port": 443, "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"name": "hy", "type": "hysteria2", "server": "9.9.9.9", "port": 443, "password": "pw"},
	}
	full := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "PROXY", "type": "select", "proxies": []interface{}{"mi", "vl"}},
			map[string]interface{}{"name": "ONLYMI", "type": "select", "proxies": []interface{}{"mi"}},
			map[string]interface{}{"name": "OUTER", "type": "select", "proxies": []interface{}{"ONLYMI"}},
			map[string]interface{}{"name": "HYG", "type": "url-test", "proxies": []interface{}{"hy", "DIRECT"}},
		},
		"rule-providers": map[string]interface{}{
			"prov": map[string]interface{}{"url": "https://example.com/list.mrs"},
		},
		"rules": []interface{}{
			"DOMAIN-SUFFIX,b.com,PROXY",
			"DOMAIN,a.com,OUTER",
			"RULE-SET,prov,mi",
			"MATCH,ONLYMI",
		},
	}
	return proxies, full
}

// srConfProxyNames / srConfGroups 按 Shadowrocket 语法(节点名称=类型,... / 名称 = 类型,成员,...)拆出节点名与组成员。
func srConfProxyNames(out string) []string {
	var names []string
	for _, line := range confSection(out, "[Proxy]") {
		names = append(names, strings.SplitN(line, "=", 2)[0])
	}
	return names
}

func srConfGroups(out string) map[string][]string {
	groups := make(map[string][]string)
	for _, line := range confSection(out, "[Proxy Group]") {
		kv := strings.SplitN(line, " = ", 2)
		fields := strings.Split(kv[1], ",")
		members := []string{}
		for _, f := range fields[1:] {
			if !strings.Contains(f, "=") {
				members = append(members, f)
			}
		}
		groups[kv[0]] = members
	}
	return groups
}

// 规格用例 {PROXY:[mi,vl], ONLYMI:[mi], FINAL,ONLYMI}(clash-to-shadowrocket):
// 写不出来的 Mieru 留注释、组被剔空就删并级联(OUTER 只含 ONLYMI),规则改 DIRECT。
func TestShadowrocketTemplatePrunesDanglingPolicies(t *testing.T) {
	proxies, full := shadowrocketPruneFixture()
	raw, err := NewShadowrocketTemplateProducer().Produce(proxies, "", &ProduceOptions{FullConfig: full})
	if err != nil {
		t.Fatal(err)
	}
	out := raw.(string)
	if !strings.Contains(out, "# 已跳过 mieru: mi(") {
		t.Errorf("跳过的节点应留注释:\n%s", out)
	}

	proxyNames := srConfProxyNames(out)
	if !reflect.DeepEqual(proxyNames, []string{"vl", "hy"}) {
		t.Errorf("[Proxy] 应为 vl、hy,得到 %v\n%s", proxyNames, out)
	}
	groups := srConfGroups(out)
	if want := map[string][]string{"PROXY": {"vl"}, "HYG": {"hy", "DIRECT"}}; !reflect.DeepEqual(groups, want) {
		t.Errorf("组 = %v, want %v\n%s", groups, want, out)
	}
	rules := confSection(out, "[Rule]")
	wantRules := []string{
		"DOMAIN-SUFFIX,b.com,PROXY",
		"DOMAIN,a.com,DIRECT",
		"RULE-SET,https://example.com/list.list,DIRECT",
		"FINAL,DIRECT",
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Errorf("规则 = %q\nwant %q", rules, wantRules)
	}
	assertNoDanglingPolicies(t, out, proxyNames, groups, rules)

	// 不改调用方的完整配置
	first := full["proxy-groups"].([]interface{})[0].(map[string]interface{})
	if !reflect.DeepEqual(first["proxies"], []interface{}{"mi", "vl"}) {
		t.Errorf("调用方的 proxy-groups 被改了: %v", first["proxies"])
	}
}

func TestRewriteDanglingRulePolicy(t *testing.T) {
	dangling := func(n string) bool { return strings.TrimSpace(n) == "GONE" }
	cases := map[string]string{
		"FINAL,GONE":                        "FINAL,DIRECT",
		"FINAL,GONE,dns-failed":             "FINAL,DIRECT,dns-failed",
		"MATCH, GONE":                       "MATCH,DIRECT",
		"DOMAIN,gone.com,GONE":              "DOMAIN,gone.com,DIRECT",
		"DOMAIN,GONE,PROXY":                 "DOMAIN,GONE,PROXY", // VALUE 碰巧同名不算
		"OR,((DOMAIN,a,b),(GEOIP,CN)),GONE": "OR,((DOMAIN,a,b),(GEOIP,CN)),DIRECT",
		"# FINAL,GONE":                      "# FINAL,GONE",
		"GEOIP,CN,DIRECT":                   "GEOIP,CN,DIRECT",
		"RULE-SET,https://x/a,b.list,PROXY": "RULE-SET,https://x/a,b.list,PROXY",
	}
	for in, want := range cases {
		if got := rewriteDanglingRulePolicy(in, dangling); got != want {
			t.Errorf("rewrite(%q) = %q, want %q", in, got, want)
		}
	}
}
