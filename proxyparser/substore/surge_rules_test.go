package substore

import (
	"reflect"
	"strings"
	"testing"
)

// Clash 模板转 Surge(clash-to-surge)时,Surge 读不懂的规则行会让整份配置拒载、一键导入失败。
// 这里覆盖:GEOSITE 展开 / 丢弃、RULE-SET 展开 / 退回地址、关键字改名、逻辑规则里的 RULE-SET。
func TestConvertClashRulesToSurgeFormatSurgeOnly(t *testing.T) {
	SetLoonRuleSetResolver(func(name string, p ClashRuleProvider, policy string) ([]string, bool) {
		switch {
		case name == "geosite:github":
			return []string{"DOMAIN-SUFFIX,github.com," + policy, "DOMAIN-REGEX,^gh.*$," + policy}, true
		case name == "cnip":
			return []string{"IP-CIDR,1.0.1.0/24," + policy, "DOMAIN,cn.example," + policy}, true
		}
		return nil, false // geosite:cn 太大 / 其它规则集抓不到
	})
	defer SetLoonRuleSetResolver(nil)

	providers := map[string]ClashRuleProvider{
		"cnip":   {Behavior: "ipcidr", URL: "https://r.example/cnip.yaml"},
		"proxy":  {Behavior: "domain", URL: "https://r.example/proxy.yaml"},
		"bin":    {Behavior: "domain", URL: "https://r.example/x.mrs"},
		"plain":  {Behavior: "classical", URL: "https://r.example/plain.list"},
		"portsd": {Behavior: "classical", URL: "https://r.example/ports.yaml"},
	}
	got, err := ConvertClashRulesToSurgeFormat([]string{
		"GEOSITE,github,🚀 GitHub",
		"GEOSITE,cn,DIRECT",
		"RULE-SET,cnip,DIRECT,no-resolve",
		"RULE-SET,proxy,Proxy",
		"RULE-SET,bin,Proxy",
		"RULE-SET,plain,Proxy",
		"RULE-SET,missing,Proxy",
		"DST-PORT,443,Proxy",
		"SRC-IP-CIDR,192.168.1.0/24,DIRECT",
		"NETWORK,udp,DIRECT",
		"DOMAIN-REGEX,^a.*$,DIRECT",
		"AND,((RULE-SET,portsd),(GEOIP,cn)),DIRECT",
		"AND,((DOMAIN-REGEX,^a$),(GEOIP,cn)),DIRECT",
		"GEOIP,private,DIRECT,no-resolve",
		"MATCH,Proxy",
	}, providers)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"DOMAIN-SUFFIX,github.com,🚀 GitHub",
		"# GEOSITE,github 展开时跳过 1 条 Surge 不支持的规则",
		"# 已忽略(Surge 没有 GEOSITE,类目内容拿不到或太大):GEOSITE,cn,DIRECT",
		"IP-CIDR,1.0.1.0/24,DIRECT,no-resolve",
		"DOMAIN,cn.example,DIRECT",
		"RULE-SET,https://r.example/proxy.list,Proxy",
		"# 已忽略(规则集是 .mrs 二进制,Surge 读不了):RULE-SET,bin,Proxy",
		"RULE-SET,https://r.example/plain.list,Proxy",
		"# 已忽略(找不到对应的 rule-provider):RULE-SET,missing,Proxy",
		"DEST-PORT,443,Proxy",
		"SRC-IP,192.168.1.0/24,DIRECT",
		"PROTOCOL,UDP,DIRECT",
		"# 已忽略(Surge 无对应规则类型):DOMAIN-REGEX,^a.*$,DIRECT",
		"AND,((RULE-SET,https://r.example/ports.list),(GEOIP,cn)),DIRECT",
		"# 已忽略(逻辑规则里有 Surge 不支持的子规则):AND,((DOMAIN-REGEX,^a$),(GEOIP,cn)),DIRECT",
		"GEOIP,private,DIRECT,no-resolve",
		"FINAL,Proxy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range got {
		if strings.HasPrefix(l, "GEOSITE") || strings.HasPrefix(l, "DST-PORT") || strings.HasPrefix(l, "DOMAIN-REGEX") {
			t.Errorf("Surge 不认的规则行漏了出去: %s", l)
		}
	}
}
