package substore

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// groupProxiesOf 取生成结果里指定代理组的 proxies 列表。
func groupProxiesOf(t *testing.T, result, groupName string) []string {
	t.Helper()
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("结果不是合法 YAML: %v", err)
	}
	groups, _ := parsed["proxy-groups"].([]any)
	for _, g := range groups {
		m, _ := g.(map[string]any)
		if m == nil || m["name"] != groupName {
			continue
		}
		raw, _ := m["proxies"].([]any)
		out := make([]string, 0, len(raw))
		for _, p := range raw {
			out = append(out, p.(string))
		}
		return out
	}
	t.Fatalf("结果里没有代理组 %q", groupName)
	return nil
}

func hasMember(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// 用户在模板里显式写了 DIRECT / REJECT,又给组配了按节点名写的 filter。
// 内置出站永远匹配不上这种正则,以前会被当成"没选中的节点"一起筛掉 ——
// 用户明明配了,产出的组里却没有。
func TestFilterKeepsBuiltInOutbounds(t *testing.T) {
	template := `
proxy-groups:
  - name: 香港节点
    type: select
    include-all: true
    filter: "香港|HK|港"
    proxies:
      - DIRECT
      - REJECT
`
	processor := NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(template, createMockProxies())
	if err != nil {
		t.Fatalf("ProcessTemplate failed: %v", err)
	}
	got := groupProxiesOf(t, result, "香港节点")

	for _, builtin := range []string{"DIRECT", "REJECT"} {
		if !hasMember(got, builtin) {
			t.Errorf("模板里显式配了 %s,filter 处理后不该被筛掉;实际组成员 = %v", builtin, got)
		}
	}
	// filter 本身仍要生效:非香港的普通节点不该混进来。
	for _, name := range got {
		if isBuiltInOutbound(name) {
			continue
		}
		if !strings.Contains(name, "香港") && !strings.Contains(name, "HK") && !strings.Contains(name, "港") {
			t.Errorf("filter 失效了,混进了非香港节点: %s(组成员 %v)", name, got)
		}
	}
}

// 全套内置出站都要豁免,不只是 DIRECT/REJECT 两个。
func TestFilterKeepsAllBuiltInOutbounds(t *testing.T) {
	template := `
proxy-groups:
  - name: 兜底组
    type: select
    include-all: true
    filter: "绝不匹配任何东西的字符串ZZZQQQ"
    proxies:
      - DIRECT
      - REJECT
      - REJECT-DROP
      - PASS
      - GLOBAL
      - COMPATIBLE
`
	processor := NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(template, createMockProxies())
	if err != nil {
		t.Fatalf("ProcessTemplate failed: %v", err)
	}
	got := groupProxiesOf(t, result, "兜底组")
	for _, builtin := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "COMPATIBLE"} {
		if !hasMember(got, builtin) {
			t.Errorf("%s 应当被保留,实际组成员 = %v", builtin, got)
		}
	}
}

// exclude-filter 的语义是"匹配上就删",用户写 exclude-filter: "DIRECT" 是**主动**要删它,
// 不能被这次的豁免拦住。豁免只针对 filter 的"没匹配上"误伤。
func TestExcludeFilterStillRemovesBuiltInWhenAsked(t *testing.T) {
	template := `
proxy-groups:
  - name: 不要直连
    type: select
    include-all: true
    exclude-filter: "DIRECT"
    proxies:
      - DIRECT
      - REJECT
`
	processor := NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(template, createMockProxies())
	if err != nil {
		t.Fatalf("ProcessTemplate failed: %v", err)
	}
	got := groupProxiesOf(t, result, "不要直连")
	if hasMember(got, "DIRECT") {
		t.Errorf("exclude-filter 明确点名 DIRECT,应当被删掉;实际组成员 = %v", got)
	}
	if !hasMember(got, "REJECT") {
		t.Errorf("没被点名的 REJECT 不该跟着消失;实际组成员 = %v", got)
	}
}

// 没配 filter 的组行为一字不变。
func TestBuiltInOutboundsUnaffectedWithoutFilter(t *testing.T) {
	template := `
proxy-groups:
  - name: 手动组
    type: select
    proxies:
      - DIRECT
      - REJECT
`
	processor := NewTemplateV3Processor(nil, nil)
	result, err := processor.ProcessTemplate(template, createMockProxies())
	if err != nil {
		t.Fatalf("ProcessTemplate failed: %v", err)
	}
	got := groupProxiesOf(t, result, "手动组")
	if !hasMember(got, "DIRECT") || !hasMember(got, "REJECT") {
		t.Errorf("没配 filter 的组不该有任何变化,实际 = %v", got)
	}
}
