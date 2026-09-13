package substore

import (
	"strings"
	"testing"
)

func TestBuildCompleteLoonConfig(t *testing.T) {
	clashConfig := &ClashConfig{
		ProxyGroups: []ClashProxyGroup{
			{
				Name:     "Proxy",
				Type:     "select",
				Proxies:  []string{"Auto", "DIRECT", "节点A"},
				URL:      "http://www.gstatic.com/generate_204",
				Interval: 300,
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
			"name":     "节点A",
			"type":     "ss",
			"server":   "1.2.3.4",
			"port":     443,
			"cipher":   "aes-256-gcm",
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
			Name:     "HK",
			Type:     "url-test",
			Proxies:  []string{"(香港|HK)"},
			URL:      "http://www.gstatic.com/generate_204",
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

// clash 的 dialer-proxy 必须变成 Loon 的 [Proxy Chain]。
//
// 不处理的话 Loon 只拿到一个普通落地节点 —— 流量直连落地、绕过入口,
// 和 clash 侧行为完全不同(用户实报)。
func TestLoonDialerProxyBecomesProxyChain(t *testing.T) {
	cfg := &ClashConfig{
		ProxyGroups: []ClashProxyGroup{
			{Name: "🚀 手动选择", Type: "select", Proxies: []string{"入口A", "新加坡落地"}},
		},
	}
	proxies := []Proxy{
		{"type": "ss", "name": "入口A", "server": "1.2.3.4", "port": 8388,
			"cipher": "aes-128-gcm", "password": "p"},
		{"type": "ss", "name": "新加坡落地", "server": "5.6.7.8", "port": 8388,
			"cipher": "aes-128-gcm", "password": "p",
			"dialer-proxy": "🚀 手动选择", "udp": true},
	}
	out, err := BuildCompleteLoonConfig(cfg, proxies)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[Proxy Chain]") {
		t.Fatalf("缺少 [Proxy Chain] 段:\n%s", out)
	}
	// 链沿用原节点名,落地节点改名 —— 这样策略组不用改就仍然指向这条链
	if !strings.Contains(out, "新加坡落地 = 🚀 手动选择, 新加坡落地 [落地], udp=true") {
		t.Errorf("链定义不对:\n%s", out)
	}
	if !strings.Contains(out, "新加坡落地 [落地]=shadowsocks,5.6.7.8") {
		t.Errorf("落地节点应改名后出现在 [Proxy] 里:\n%s", out)
	}
	// 没有 dialer-proxy 的节点保持原样
	if !strings.Contains(out, "入口A=shadowsocks,1.2.3.4") {
		t.Errorf("普通节点不该被改名:\n%s", out)
	}
}

// ——— GEOSITE:Loon 没有这个规则类型,必须展开或引用,绝不原样透传 ———

// Loon 官方文档(https://nsloon.app/docs/Rule/ 各子页)列出的、[Rule] 段真正认识的关键字。
// 注意这份名单不能照抄 Surge:Surge 有 SRC-IP-CIDR / PROCESS-NAME / DST-PORT,Loon 都没有。
var loonKnownRuleKeywords = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true,
	"IP-CIDR": true, "IP-CIDR6": true, "GEOIP": true, "IP-ASN": true,
	"SRC-PORT": true, "DEST-PORT": true,
	"URL-REGEX": true, "USER-AGENT": true, "PROTOCOL": true,
	"AND": true, "OR": true, "NOT": true, "FINAL": true,
}

// loonRuleLinesOf 抠出 [Rule] 段里真正会被执行的行(跳过注释)。
func loonRuleLinesOf(loonConfig string) []string {
	var out []string
	section := ""
	for _, ln := range strings.Split(loonConfig, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = t
			continue
		}
		if section != "[Rule]" || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// 装了解析器时:GEOSITE 类目被展开成 DOMAIN/DOMAIN-SUFFIX 内联进 [Rule]。
func TestLoonGeositeInlinedByResolver(t *testing.T) {
	var gotURL, gotBehavior, gotPolicy string
	SetLoonRuleSetResolver(func(_ string, p ClashRuleProvider, policy string) ([]string, bool) {
		gotURL, gotBehavior, gotPolicy = p.URL, p.Behavior, policy
		return []string{
			"DOMAIN,github.com," + policy,
			"DOMAIN-SUFFIX,githubusercontent.com," + policy,
			// 解析器可能带出 Loon 读不懂的行(classical 规则集里就有),必须被过滤掉
			"DOMAIN-REGEX,^gh\\..*$," + policy,
		}, true
	})
	defer SetLoonRuleSetResolver(nil)

	cfg := &ClashConfig{
		Rules:       []string{"GEOSITE,GitHub,🚀 GitHub", "MATCH,🐟 漏网之鱼"},
		ProxyGroups: []ClashProxyGroup{{Name: "🚀 GitHub", Type: "select", Proxies: []string{"DIRECT"}}},
	}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 类目名原样小写拼进上游仓库路径
	if want := "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.list"; gotURL != want {
		t.Errorf("geosite URL = %q, want %q", gotURL, want)
	}
	if gotBehavior != "domain" {
		t.Errorf("geosite 清单每行是裸域名,应按 behavior=domain 解析,实际 %q", gotBehavior)
	}
	if gotPolicy != "🚀 GitHub" {
		t.Errorf("policy = %q", gotPolicy)
	}
	if !strings.Contains(out, "DOMAIN,github.com,🚀 GitHub") ||
		!strings.Contains(out, "DOMAIN-SUFFIX,githubusercontent.com,🚀 GitHub") {
		t.Errorf("展开后的域名规则没内联进来:\n%s", out)
	}
	if strings.Contains(out, "DOMAIN-REGEX") {
		t.Errorf("解析器带出的 DOMAIN-REGEX 应被过滤(Loon 读不懂):\n%s", out)
	}
	for _, ln := range loonRuleLinesOf(out) {
		if strings.HasPrefix(strings.ToUpper(ln), "GEOSITE") {
			t.Errorf("GEOSITE 原样透传了:%s", ln)
		}
	}
}

// 没装解析器(模块是纯函数、不联网)时:退化成 [Remote Rule] 引用 classical 清单,
// 而不是把 Loon 读不懂的 GEOSITE 行扔进 [Rule],更不是静默丢掉。
func TestLoonGeositeFallsBackToRemoteRule(t *testing.T) {
	SetLoonRuleSetResolver(nil)
	cfg := &ClashConfig{
		Rules:       []string{"GEOSITE,geolocation-!cn,🚀 手动选择", "MATCH,🐟 漏网之鱼"},
		ProxyGroups: []ClashProxyGroup{{Name: "🚀 手动选择", Type: "select", Proxies: []string{"DIRECT"}}},
	}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[Remote Rule]") {
		t.Fatalf("缺少 [Remote Rule] 段:\n%s", out)
	}
	// classical 清单每行已经是 `DOMAIN-SUFFIX,x` —— 正好是 Loon 远程规则要的格式
	want := "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/geolocation-!cn.list, policy=🚀 手动选择, tag=geosite-geolocation-!cn, enabled=true"
	if !strings.Contains(out, want) {
		t.Errorf("远程规则行不对,期望包含:\n%s\n实际:\n%s", want, out)
	}
	for _, ln := range loonRuleLinesOf(out) {
		if strings.HasPrefix(strings.ToUpper(ln), "GEOSITE") {
			t.Errorf("GEOSITE 原样透传了:%s", ln)
		}
	}
}

// 解析器说「解析不了」时,同样退化到 [Remote Rule],不能让规则凭空消失。
func TestLoonGeositeResolverFailureFallsBackToRemoteRule(t *testing.T) {
	SetLoonRuleSetResolver(func(string, ClashRuleProvider, string) ([]string, bool) {
		return nil, false
	})
	defer SetLoonRuleSetResolver(nil)

	cfg := &ClashConfig{Rules: []string{"GEOSITE,cn,🎯 全球直连"}}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "geo/geosite/classical/cn.list, policy=🎯 全球直连") {
		t.Errorf("解析失败时应退化为远程规则:\n%s", out)
	}
}

// ——— A2:白名单必须按 Loon 文档来,不是照抄 Surge ———

func TestLoonRuleKeywordTranslationAndDropping(t *testing.T) {
	SetLoonRuleSetResolver(nil)
	cfg := &ClashConfig{
		Rules: []string{
			// Loon 拼作 DEST-PORT —— 改名,不是丢弃
			"DST-PORT,443,🚀 手动选择",
			// Loon 的 IP 规则里没有 SRC-IP-CIDR;iOS 上也没有进程规则
			"SRC-IP-CIDR,192.168.1.0/24,🎯 全球直连",
			"PROCESS-NAME,Telegram,🚀 手动选择",
			// Loon 没有域名正则规则
			"DOMAIN-REGEX,^ad\\..*\\.com$,🎯 全球直连",
			// clash 的 NETWORK 等价于 Loon 的 PROTOCOL(取值大写)
			"NETWORK,udp,🚀 手动选择",
			// 逻辑规则:子规则里的 DST-PORT 也要跟着改名
			"AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,8080)),🚀 手动选择",
			// 子规则里有 Loon 不认识的关键字 → 整条执行不了,丢弃
			"OR,((PROCESS-NAME,Telegram),(DOMAIN,t.me)),🚀 手动选择",
			// 下面这些 Loon 确实有,原样保留
			"DOMAIN,example.com,🚀 手动选择",
			"DOMAIN-SUFFIX,google.com,🚀 手动选择",
			"DOMAIN-KEYWORD,github,🚀 手动选择",
			"IP-CIDR,1.2.3.0/24,🎯 全球直连,no-resolve",
			"IP-CIDR6,2001:db8::/32,🎯 全球直连",
			"GEOIP,cn,🎯 全球直连,no-resolve",
			"IP-ASN,13335,🚀 手动选择",
			"SRC-PORT,1234,🎯 全球直连",
			"URL-REGEX,^http://example\\.com,🚀 手动选择",
			"USER-AGENT,Telegram*,🚀 手动选择",
			"PROTOCOL,QUIC,REJECT",
			"MATCH,🐟 漏网之鱼",
		},
		ProxyGroups: []ClashProxyGroup{{Name: "🚀 手动选择", Type: "select", Proxies: []string{"DIRECT"}}},
	}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 产出的每一行 Loon 都得读得懂
	for _, ln := range loonRuleLinesOf(out) {
		kw := strings.ToUpper(strings.TrimSpace(strings.SplitN(ln, ",", 2)[0]))
		if !loonKnownRuleKeywords[kw] {
			t.Errorf("产出了 Loon 不认识的关键字 %q:%s", kw, ln)
		}
	}

	mustHave := []string{
		"DEST-PORT,443,🚀 手动选择",
		"PROTOCOL,UDP,🚀 手动选择",
		"AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,8080)),🚀 手动选择",
		"DOMAIN,example.com,🚀 手动选择",
		"DOMAIN-SUFFIX,google.com,🚀 手动选择",
		"DOMAIN-KEYWORD,github,🚀 手动选择",
		"IP-CIDR,1.2.3.0/24,🎯 全球直连,no-resolve",
		"IP-CIDR6,2001:db8::/32,🎯 全球直连",
		"GEOIP,cn,🎯 全球直连,no-resolve",
		"IP-ASN,13335,🚀 手动选择",
		"SRC-PORT,1234,🎯 全球直连",
		"URL-REGEX,^http://example\\.com,🚀 手动选择",
		"USER-AGENT,Telegram*,🚀 手动选择",
		"PROTOCOL,QUIC,REJECT",
		"FINAL,🐟 漏网之鱼",
	}
	for _, want := range mustHave {
		if !strings.Contains(out, want) {
			t.Errorf("缺少规则 %q:\n%s", want, strings.Join(loonRuleLinesOf(out), "\n"))
		}
	}

	// 丢掉的三类必须留痕,不能静默消失
	for _, dropped := range []string{"SRC-IP-CIDR,192.168.1.0/24", "PROCESS-NAME,Telegram", "DOMAIN-REGEX,^ad\\..*\\.com$"} {
		if !strings.Contains(out, "# 已忽略") || !strings.Contains(out, dropped) {
			t.Errorf("规则 %q 被静默丢弃,输出里没有注释痕迹:\n%s", dropped, out)
		}
	}
	if strings.Contains(out, "OR,((PROCESS-NAME") && !strings.Contains(out, "# 已忽略(Loon 无对应规则类型):OR,((PROCESS-NAME") {
		t.Errorf("含不支持子规则的逻辑规则应被丢弃并留痕:\n%s", out)
	}
}

// RULE-SET 的解析结果同样要过一道:classical 规则集里可能夹带 Loon 读不懂的行。
func TestLoonRuleSetResolvedLinesAreFiltered(t *testing.T) {
	SetLoonRuleSetResolver(func(_ string, _ ClashRuleProvider, policy string) ([]string, bool) {
		return []string{
			"DOMAIN,ok.com," + policy,
			"PROCESS-NAME,curl," + policy,
			"DST-PORT,8443," + policy,
		}, true
	})
	defer SetLoonRuleSetResolver(nil)

	cfg := &ClashConfig{
		Rules:         []string{"RULE-SET,mixed,🎯 全球直连"},
		RuleProviders: map[string]ClashRuleProvider{"mixed": {Type: "http", Behavior: "classical", URL: "https://example.com/mixed.yaml"}},
	}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "DOMAIN,ok.com,🎯 全球直连") {
		t.Errorf("可用的行应被内联:\n%s", out)
	}
	if !strings.Contains(out, "DEST-PORT,8443,🎯 全球直连") {
		t.Errorf("DST-PORT 应改名成 DEST-PORT:\n%s", out)
	}
	if strings.Contains(out, "PROCESS-NAME") {
		t.Errorf("Loon 没有进程规则,不该内联:\n%s", out)
	}
	if !strings.Contains(out, "跳过 1 条 Loon 不支持的规则") {
		t.Errorf("过滤掉的行数应有交代:\n%s", out)
	}
}

// ——— A3:kelee 模板下,首跳是中转组的链 ———

// 不传 extraPolicies 时行为与从前一致:首跳是模板/外部组名 → 无从校验 → 不出链。
func TestLoonKeleeChainDroppedWithoutExtraPolicies(t *testing.T) {
	proxies := keleeRelayProxies()
	out, err := BuildLoonKeleeConfig(proxies)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "[Proxy Chain]") {
		t.Errorf("首跳无从校验时不该出链:\n%s", out)
	}
}

// 传了中转组名:链要出来,而且这个组必须在 [Proxy Group] 里**真实存在** ——
// 只加白名单不渲染组,等于把「静默丢链」换成「Loon 整份拒载」。
func TestLoonKeleeChainWithExtraPolicies(t *testing.T) {
	proxies := keleeRelayProxies()
	out, err := BuildLoonKeleeConfigWithPolicies(proxies, []string{"中转组", "", "中转组"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[Proxy Chain]") {
		t.Fatalf("缺少 [Proxy Chain] 段:\n%s", out)
	}
	if !strings.Contains(out, "落地 = 中转组, 落地 [落地]") {
		t.Errorf("链定义不对:\n%s", out)
	}
	// 组要被渲染出来,成员取非链式节点(链式节点放进来会绕回链自身)
	groupLine := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "中转组 = select") {
			groupLine = ln
		}
	}
	if groupLine == "" {
		t.Fatalf("首跳组没有被渲染进 [Proxy Group],Loon 会因悬空引用拒载:\n%s", out)
	}
	if !strings.Contains(groupLine, "入口A") {
		t.Errorf("首跳组应包含非链式节点:%s", groupLine)
	}
	if strings.Contains(groupLine, "落地") {
		t.Errorf("链式节点不该出现在自己的首跳组里:%s", groupLine)
	}
	// 只渲染一次
	if strings.Count(out, "中转组 = select") != 1 {
		t.Errorf("首跳组被渲染了多次:\n%s", out)
	}
}

// 没被任何节点当首跳的组名不渲染 —— 调用方可以把 clash 侧全部组名一股脑传进来,
// 不会因此给 kelee 模板塞一堆没人用的组。
func TestLoonKeleeUnreferencedExtraPolicyIsNotRendered(t *testing.T) {
	out, err := BuildLoonKeleeConfigWithPolicies(keleeRelayProxies(), []string{"中转组", "没人用的组"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "中转组 = select") {
		t.Errorf("被当首跳的组应渲染:\n%s", out)
	}
	if strings.Contains(out, "没人用的组") {
		t.Errorf("没人引用的组不该塞进配置:\n%s", out)
	}
}

// 首跳指向 kelee 模板自带的组时,采信即可 —— 再渲染一遍就是重名组。
func TestLoonKeleeExtraPolicyAlreadyInTemplateIsNotDuplicated(t *testing.T) {
	proxies := []Proxy{
		{"type": "ss", "name": "入口A", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "p"},
		{"type": "ss", "name": "落地", "server": "5.6.7.8", "port": 8388, "cipher": "aes-128-gcm", "password": "p",
			"dialer-proxy": "香港手动策略"},
	}
	out, err := BuildLoonKeleeConfigWithPolicies(proxies, []string{"香港手动策略"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "落地 = 香港手动策略, 落地 [落地]") {
		t.Errorf("首跳是模板自带组时链应成立:\n%s", out)
	}
	if strings.Contains(out, "香港手动策略 = select,") {
		t.Errorf("模板里已有的组不该被重复渲染:\n%s", out)
	}
}

func keleeRelayProxies() []Proxy {
	return []Proxy{
		{"type": "ss", "name": "入口A", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "p"},
		{"type": "ss", "name": "落地", "server": "5.6.7.8", "port": 8388, "cipher": "aes-128-gcm", "password": "p",
			"dialer-proxy": "中转组"},
	}
}

// 首跳指向不存在的策略时,退回普通节点 —— 悬空引用会让 Loon 整份拒载。
func TestLoonDanglingDialerProxyFallsBack(t *testing.T) {
	cfg := &ClashConfig{}
	proxies := []Proxy{
		{"type": "ss", "name": "落地", "server": "5.6.7.8", "port": 8388,
			"cipher": "aes-128-gcm", "password": "p", "dialer-proxy": "并不存在的组"},
	}
	out, err := BuildCompleteLoonConfig(cfg, proxies)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "[Proxy Chain]") {
		t.Errorf("首跳不存在时不该生成链:\n%s", out)
	}
	if !strings.Contains(out, "落地=shadowsocks,5.6.7.8") {
		t.Errorf("应保留为普通节点:\n%s", out)
	}
}

// RULE-SET 行尾的 no-resolve 必须跟着展开出来的 IP 规则走。
//
// clash 把 no-resolve 挂在 RULE-SET 那一行上,而我们把规则集展开成一条条内联规则 ——
// 不搬过去的话不是「规则失效」,而是更隐蔽的行为反转:Loon 会对每条 IP 规则先做 DNS
// 解析,本该直连的查询被提前送出去。域名规则不解析,给它加 no-resolve 是语法噪音。
func TestLoonRuleSetNoResolveFollowsInlinedIPRules(t *testing.T) {
	SetLoonRuleSetResolver(func(_ string, _ ClashRuleProvider, policy string) ([]string, bool) {
		return []string{"IP-CIDR,1.1.1.0/24," + policy, "DOMAIN-SUFFIX,cn," + policy}, true
	})
	defer SetLoonRuleSetResolver(nil)

	cfg := &ClashConfig{
		Rules: []string{"RULE-SET,cnip,🎯 全球直连,no-resolve", "MATCH,🚀 手动选择"},
		RuleProviders: map[string]ClashRuleProvider{
			"cnip": {Type: "http", Behavior: "ipcidr", URL: "https://e.com/cnip.yaml"},
		},
		ProxyGroups: []ClashProxyGroup{
			{Name: "🎯 全球直连", Type: "select", Proxies: []string{"DIRECT"}},
			{Name: "🚀 手动选择", Type: "select", Proxies: []string{"DIRECT"}},
		},
	}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "IP-CIDR,1.1.1.0/24,🎯 全球直连,no-resolve") {
		t.Errorf("no-resolve 没传到内联的 IP 规则上:\n%s", out)
	}
	if strings.Contains(out, "DOMAIN-SUFFIX,cn,🎯 全球直连,no-resolve") {
		t.Errorf("no-resolve 不该加到域名规则上:\n%s", out)
	}
}

// 规则集大到解析不了时的两条退路,都不能让规则凭空消失:
// .yaml 猜得到同目录 .list → 交给 Loon 自己拉([Remote Rule]);
// .mrs 是二进制、猜地址只会 404 → 不产出错地址,但必须在 [Rule] 里留痕。
func TestLoonUnresolvableRuleSetDegradesVisibly(t *testing.T) {
	SetLoonRuleSetResolver(func(_ string, _ ClashRuleProvider, _ string) ([]string, bool) {
		return nil, false // 模拟超过行数上限 / 抓不到
	})
	defer SetLoonRuleSetResolver(nil)

	cfg := &ClashConfig{
		Rules: []string{"RULE-SET,big,🎯 全球直连", "RULE-SET,bin,🎯 全球直连", "MATCH,🚀 手动选择"},
		RuleProviders: map[string]ClashRuleProvider{
			"big": {Type: "http", Behavior: "domain", URL: "https://e.com/big.yaml"},
			"bin": {Type: "http", Behavior: "domain", URL: "https://e.com/big.mrs"},
		},
		ProxyGroups: []ClashProxyGroup{
			{Name: "🎯 全球直连", Type: "select", Proxies: []string{"DIRECT"}},
			{Name: "🚀 手动选择", Type: "select", Proxies: []string{"DIRECT"}},
		},
	}
	out, err := BuildCompleteLoonConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[Remote Rule]") || !strings.Contains(out, "big.list") {
		t.Errorf(".yaml 规则集应退化成 [Remote Rule]:\n%s", out)
	}
	if !strings.Contains(out, "# 已忽略") {
		t.Errorf(".mrs 规则集拿不到时必须留痕,不能静默消失:\n%s", out)
	}
}
