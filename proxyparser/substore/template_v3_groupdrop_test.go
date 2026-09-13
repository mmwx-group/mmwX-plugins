package substore

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 本文件专治「V3 模板丢组」:用户 44 个代理组转出来只剩 25 个。
//
// 丢组的直接动作是 processProxyGroups「成员为空就删组」,但真正的 bug 在上游——
// 一堆本来有成员的组被算成了「假空」:
//
//	B1 filter/exclude-filter 用了 RE2 不支持的先行断言,编译失败被静默吞成"全不匹配";
//	B2 providers 恒为 nil,use: / include-all-providers 取不到任何成员;
//	B4 条目是 YAML 别名 / 合并键,根本没被当成 mapping 处理。
//
// 下面的用例逐条钉死这些成因,同时保证「真正该空的组」仍按既有语义删掉。

func groupDropNodes() []map[string]any {
	return []map[string]any{
		{"name": "🇭🇰 香港01", "type": "ss", "server": "1.1.1.1", "port": 443},
		{"name": "🇭🇰 香港02", "type": "ss", "server": "1.1.1.2", "port": 443},
		{"name": "🇯🇵 日本01", "type": "vmess", "server": "1.1.1.3", "port": 443},
		{"name": "🇺🇸 美国01", "type": "trojan", "server": "1.1.1.4", "port": 443},
		{"name": "XX 未知地区01", "type": "ss", "server": "1.1.1.5", "port": 443},
	}
}

type parsedGroup struct {
	name    string
	proxies []string
}

// parseGroups 从产物里按顺序取出 proxy-groups 的组名与成员
func parseGroups(t *testing.T, out string) []parsedGroup {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("产物不是合法 YAML: %v", err)
	}
	if len(doc.Content) == 0 {
		t.Fatalf("产物为空")
	}
	var groups []parsedGroup
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "proxy-groups" {
			continue
		}
		for _, g := range root.Content[i+1].Content {
			var pg parsedGroup
			for j := 0; j+1 < len(g.Content); j += 2 {
				switch g.Content[j].Value {
				case "name":
					pg.name = g.Content[j+1].Value
				case "proxies":
					for _, item := range g.Content[j+1].Content {
						pg.proxies = append(pg.proxies, item.Value)
					}
				}
			}
			groups = append(groups, pg)
		}
	}
	return groups
}

func groupByName(groups []parsedGroup, name string) (parsedGroup, bool) {
	for _, g := range groups {
		if g.name == name {
			return g, true
		}
	}
	return parsedGroup{}, false
}

func groupNamesOf(groups []parsedGroup) []string {
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.name)
	}
	return names
}

// 综合用例:一份把四类「假空」成因全踩一遍的模板。
// 12 个组里只有「🇰🇷 韩国节点」是真的没有对应节点,其余 11 个都必须活下来。
func TestTemplateV3NoGroupLostToFakeEmpty(t *testing.T) {
	const tpl = `
x-base: &base
  type: select
  proxies:
    - "🇭🇰 香港01"
    - "🇯🇵 日本01"
x-alias-group: &aliasgroup
  name: "🔗 别名组"
  type: select
  proxies:
    - "🇺🇸 美国01"
x-nodes: &nodelist
  - "🇯🇵 日本01"
  - "🇺🇸 美国01"
proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - "♻️ 自动选择"
      - "🚫 非香港"
      - "🚫 非港日"
      - "🈚 集合组"
      - "🈳 全集合"
      - "🔗 别名组"
      - "🧩 合并键组"
      - "📎 别名成员组"
      - "🎯 只留香港"
      - "🇰🇷 韩国节点"
      - DIRECT
  - name: "♻️ 自动选择"
    type: url-test
    include-all-proxies: true
  - name: "🚫 非香港"
    type: select
    filter: "^((?!香港).)*$"
  - name: "🚫 非港日"
    type: select
    filter: "(^(?!.*(香港|日本)).*)"
  - name: "🈚 集合组"
    type: select
    use:
      - 机场A
  - name: "🈳 全集合"
    type: select
    include-all-providers: true
  - *aliasgroup
  - name: "🧩 合并键组"
    <<: *base
  - name: "📎 别名成员组"
    type: select
    proxies: *nodelist
  - name: "🎯 只留香港"
    type: select
    include-all-proxies: true
    exclude-filter: "^((?!香港).)*$"
  - name: "🇰🇷 韩国节点"
    type: url-test
    include-all-proxies: true
    filter: "🇰🇷|韩国|KR"
  - name: "🧨 只引韩国"
    type: select
    proxies:
      - "🇰🇷 韩国节点"
rules:
  - MATCH,🚀 节点选择
`

	const templateGroups = 12 // 模板里写了几个组

	p := NewTemplateV3Processor(nil, nil)
	out, err := p.ProcessTemplate(tpl, groupDropNodes())
	if err != nil {
		t.Fatalf("ProcessTemplate 失败: %v", err)
	}
	groups := parseGroups(t, out)
	t.Logf("模板组数 = %d, 产物组数 = %d, 丢 %d 组: %v",
		templateGroups, len(groups), templateGroups-len(groups), groupNamesOf(groups))

	// 只允许「🇰🇷 韩国节点」这一个真空组消失
	if len(groups) != templateGroups-1 {
		t.Errorf("期望只丢 1 个真空组(🇰🇷 韩国节点),实际丢了 %d 个: %v",
			templateGroups-len(groups), groupNamesOf(groups))
	}
	if _, ok := groupByName(groups, "🇰🇷 韩国节点"); ok {
		t.Error("🇰🇷 韩国节点 没有任何匹配节点,应按既有语义删掉")
	}

	// B1:先行断言 filter 不能再把组筛空
	if g, ok := groupByName(groups, "🚫 非香港"); !ok {
		t.Error("🚫 非香港 组不见了(先行断言 filter 被吞成全不匹配)")
	} else {
		want := []string{"🇯🇵 日本01", "🇺🇸 美国01", "XX 未知地区01"}
		if strings.Join(g.proxies, ",") != strings.Join(want, ",") {
			t.Errorf("🚫 非香港 成员 = %v, 期望 %v", g.proxies, want)
		}
	}
	if g, ok := groupByName(groups, "🚫 非港日"); !ok {
		t.Error("🚫 非港日 组不见了")
	} else {
		want := []string{"🇺🇸 美国01", "XX 未知地区01"}
		if strings.Join(g.proxies, ",") != strings.Join(want, ",") {
			t.Errorf("🚫 非港日 成员 = %v, 期望 %v", g.proxies, want)
		}
	}
	// exclude-filter 侧同理:改写后「排除非香港」= 只留香港
	if g, ok := groupByName(groups, "🎯 只留香港"); !ok {
		t.Error("🎯 只留香港 组不见了")
	} else {
		want := []string{"🇭🇰 香港01", "🇭🇰 香港02"}
		if strings.Join(g.proxies, ",") != strings.Join(want, ",") {
			t.Errorf("🎯 只留香港 成员 = %v, 期望 %v", g.proxies, want)
		}
	}

	// B2:providers 为 nil 时 use:/include-all-providers 不能把组搞没
	for _, name := range []string{"🈚 集合组", "🈳 全集合"} {
		g, ok := groupByName(groups, name)
		if !ok {
			t.Errorf("%s 组不见了(providers 为 nil 导致假空)", name)
			continue
		}
		if len(g.proxies) != len(groupDropNodes()) {
			t.Errorf("%s 期望用节点池兜底(%d 个),实际 %v", name, len(groupDropNodes()), g.proxies)
		}
	}

	// B4:YAML 别名条目 / 合并键 / 别名成员
	if g, ok := groupByName(groups, "🔗 别名组"); !ok {
		t.Error("🔗 别名组 不见了(整条是 YAML 别名)")
	} else if strings.Join(g.proxies, ",") != "🇺🇸 美国01" {
		t.Errorf("🔗 别名组 成员 = %v, 期望 [🇺🇸 美国01]", g.proxies)
	}
	if g, ok := groupByName(groups, "🧩 合并键组"); !ok {
		t.Error("🧩 合并键组 不见了(<<: *base 没展开)")
	} else if strings.Join(g.proxies, ",") != "🇭🇰 香港01,🇯🇵 日本01" {
		t.Errorf("🧩 合并键组 成员 = %v, 期望 [🇭🇰 香港01 🇯🇵 日本01]", g.proxies)
	}
	if g, ok := groupByName(groups, "📎 别名成员组"); !ok {
		t.Error("📎 别名成员组 不见了(proxies: *nodelist 没解引用)")
	} else if strings.Join(g.proxies, ",") != "🇯🇵 日本01,🇺🇸 美国01" {
		t.Errorf("📎 别名成员组 成员 = %v, 期望 [🇯🇵 日本01 🇺🇸 美国01]", g.proxies)
	}

	// 真空组被删后,引用它的组不能留下 `proxies: []`(mihomo 会拒载)
	if g, ok := groupByName(groups, "🧨 只引韩国"); !ok {
		t.Error("🧨 只引韩国 不该整组消失,应留下 DIRECT 兜底")
	} else if strings.Join(g.proxies, ",") != "DIRECT" {
		t.Errorf("🧨 只引韩国 成员 = %v, 期望 [DIRECT]", g.proxies)
	}
	if strings.Contains(out, "proxies: []") {
		t.Errorf("产物里出现 `proxies: []`,mihomo 会直接拒载:\n%s", out)
	}

	// 上层组里对已删组的引用要清掉,其余引用一个都不能少
	if g, ok := groupByName(groups, "🚀 节点选择"); !ok {
		t.Error("🚀 节点选择 不见了")
	} else {
		for _, ref := range g.proxies {
			if ref == "🇰🇷 韩国节点" {
				t.Error("🚀 节点选择 里还留着已删组 🇰🇷 韩国节点 的悬空引用")
			}
		}
		if len(g.proxies) != 10 { // 原 11 项减掉 🇰🇷 韩国节点
			t.Errorf("🚀 节点选择 成员数 = %d, 期望 10: %v", len(g.proxies), g.proxies)
		}
	}
}

// 编译失败且改写不了的正则(正向先行断言),filter 必须降级成"不过滤",
// 而不是把组筛空 → 删组。
func TestTemplateV3UnrewritableFilterKeepsGroup(t *testing.T) {
	const tpl = `
proxy-groups:
  - name: "🌀 怪正则组"
    type: select
    include-all-proxies: true
    filter: "(?=香港)\\d+"
  - name: "🌀 怪排除组"
    type: select
    include-all-proxies: true
    exclude-filter: "(?=香港)\\d+"
rules: []
`
	p := NewTemplateV3Processor(nil, nil)
	out, err := p.ProcessTemplate(tpl, groupDropNodes())
	if err != nil {
		t.Fatalf("ProcessTemplate 失败: %v", err)
	}
	groups := parseGroups(t, out)
	if len(groups) != 2 {
		t.Fatalf("期望 2 个组都保留,实际 %d 个: %v", len(groups), groupNamesOf(groups))
	}
	for _, g := range groups {
		if len(g.proxies) != len(groupDropNodes()) {
			t.Errorf("%s 期望降级成全量保留(%d 个),实际 %v", g.name, len(groupDropNodes()), g.proxies)
		}
	}
}

// providers 真的传进来时,use: 必须老老实实用 provider 的节点,不能走兜底
func TestTemplateV3ProvidersUsedWhenAvailable(t *testing.T) {
	const tpl = `
proxy-groups:
  - name: "🈚 集合组"
    type: select
    use:
      - 机场A
rules: []
`
	providers := map[string][]string{"机场A": {"A-节点1", "A-节点2"}}
	p := NewTemplateV3Processor(nil, providers)
	out, err := p.ProcessTemplate(tpl, groupDropNodes())
	if err != nil {
		t.Fatalf("ProcessTemplate 失败: %v", err)
	}
	g, ok := groupByName(parseGroups(t, out), "🈚 集合组")
	if !ok {
		t.Fatal("🈚 集合组 不见了")
	}
	if strings.Join(g.proxies, ",") != "A-节点1,A-节点2" {
		t.Errorf("成员 = %v, 期望 [A-节点1 A-节点2]", g.proxies)
	}
}

// 兜底只在"一个成员都凑不出来"时发生:组里本来就有显式成员/节点的,一个都不能多给
func TestTemplateV3ProviderFallbackOnlyWhenGroupWouldBeEmpty(t *testing.T) {
	const tpl = `
proxy-groups:
  - name: "🧷 有显式成员"
    type: select
    use:
      - 机场A
    proxies:
      - DIRECT
  - name: "🧷 有节点"
    type: select
    include-all-proxies: true
    use:
      - 机场A
rules: []
`
	p := NewTemplateV3Processor(nil, nil)
	out, err := p.ProcessTemplate(tpl, groupDropNodes())
	if err != nil {
		t.Fatalf("ProcessTemplate 失败: %v", err)
	}
	groups := parseGroups(t, out)
	if g, ok := groupByName(groups, "🧷 有显式成员"); !ok {
		t.Error("🧷 有显式成员 组不见了")
	} else if strings.Join(g.proxies, ",") != "DIRECT" {
		t.Errorf("🧷 有显式成员 成员 = %v, 期望只有 [DIRECT](不该被节点池兜底撑大)", g.proxies)
	}
	if g, ok := groupByName(groups, "🧷 有节点"); !ok {
		t.Error("🧷 有节点 组不见了")
	} else if len(g.proxies) != len(groupDropNodes()) {
		t.Errorf("🧷 有节点 成员 = %v, 期望就是 include-all-proxies 的 %d 个节点", g.proxies, len(groupDropNodes()))
	}
}

// 内置地区组:不能出现重名的「🌐 其他地区」,且它只该收没被任何地区命中的节点
func TestTemplateV3RegionGroupsNoDuplicateOtherRegions(t *testing.T) {
	const tpl = `
add-region-proxy-groups: true
proxy-groups:
  - name: "🚀 选择"
    type: select
    proxies:
      - "__REGION_PROXY_GROUPS__"
rules: []
`
	p := NewTemplateV3Processor(nil, nil)
	out, err := p.ProcessTemplate(tpl, groupDropNodes())
	if err != nil {
		t.Fatalf("ProcessTemplate 失败: %v", err)
	}
	groups := parseGroups(t, out)

	seen := make(map[string]int)
	for _, g := range groups {
		seen[g.name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("组名 %q 出现了 %d 次,重名组会让客户端拒载", name, n)
		}
	}

	g, ok := groupByName(groups, OtherRegionsGroupName)
	if !ok {
		t.Fatalf("%s 组不见了: %v", OtherRegionsGroupName, groupNamesOf(groups))
	}
	if strings.Join(g.proxies, ",") != "XX 未知地区01" {
		t.Errorf("%s 成员 = %v, 期望只有 [XX 未知地区01]", OtherRegionsGroupName, g.proxies)
	}
}

func TestRewriteNegativeLookaheadToExclusion(t *testing.T) {
	cases := []struct {
		pattern string
		body    string
		ok      bool
	}{
		{`^((?!香港).)*$`, "香港", true},
		{`^((?!香港|日本).)*$`, "香港|日本", true},
		{`(^(?!.*(香港|日本)).*)`, "(香港|日本)", true},
		{`^(?!.*港)`, "港", true},
		{`^(?!香港).*`, "^(?:香港)", true},
		{`^(?!香港).*$`, "^(?:香港)", true},
		// 认不出来的形态一律返回 false,交给降级逻辑
		{`香港`, "", false},
		{`(?=香港)`, "", false},
		{`^((?!香港).)*$|日本`, "", false},
		{`^(?!香港)\d{3}`, "", false},
	}
	for _, c := range cases {
		body, ok := rewriteNegativeLookaheadToExclusion(c.pattern)
		if ok != c.ok || body != c.body {
			t.Errorf("rewriteNegativeLookaheadToExclusion(%q) = (%q,%v), 期望 (%q,%v)",
				c.pattern, body, ok, c.body, c.ok)
		}
	}
}

// 内置地区组的正则必须全部能被 RE2(经 normalize 后)编译,否则该组永远空、永远被删
func TestBuiltinRegionFiltersAllCompile(t *testing.T) {
	for _, r := range RegionProxyGroups {
		if _, err := compileCompatibleRegex(r.Filter); err != nil {
			t.Errorf("地区组 %s 的 filter 编译失败: %v", r.Name, err)
		}
	}
	if _, err := compileCompatibleRegex(GetOtherRegionsExcludeFilter()); err != nil {
		t.Errorf("%s 的 exclude-filter 编译失败: %v", OtherRegionsGroupName, err)
	}
	for _, name := range GetRegionProxyGroupNames() {
		if name == OtherRegionsGroupName {
			continue
		}
		if strings.Contains(GetOtherRegionsExcludeFilter(), name) {
			t.Errorf("exclude-filter 里混进了组名 %q", name)
		}
	}
}
