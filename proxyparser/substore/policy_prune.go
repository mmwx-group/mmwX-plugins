package substore

import "strings"

// 生成完整配置(clash-to-surge / clash-to-shadowrocket)时,不支持的节点类型(WireGuard、
// 各种目标客户端没有的协议)会被静默丢掉,但 clash 的 proxy-groups / rules 是原样搬过去的,
// 组里、规则里、underlying-proxy 里还留着这些节点的名字 —— 指向一个不存在的策略。
//
// 这里的清理只认「已知但没输出」的名字:输入里有、却没能输出的节点,以及因此被剔空而删掉的组。
// 不认识的名字(DIRECT / REJECT 等内置策略、正则过滤、别处定义的策略)一律原样保留,避免误伤。

// policyGroupMembers 是一个代理组的名字与成员(按原顺序)。
type policyGroupMembers struct {
	Name    string
	Members []string
}

// policyPruneResult 是一次剔除的结果。
type policyPruneResult struct {
	// Members 与输入的组一一对应,是剔除悬空名字后的成员。
	Members [][]string
	// Removed 是被剔空而删除的组:原本有成员、剔除后一个不剩。
	// 原本就没有成员的组(靠 include-all / filter / use 取节点)不算,保持原样。
	Removed map[string]bool
	dropped map[string]bool
}

// Dangling 判断一个策略名是否悬空:是没输出的节点,或是被删掉的组。
func (r *policyPruneResult) Dangling(name string) bool {
	name = strings.TrimSpace(name)
	return r.Removed[name] || r.dropped[name]
}

// prunePolicyGroups 按实际输出的节点剔除组成员里的悬空名字。
// 组被剔空就删掉,并级联:引用它的组再剔一遍,直到不再变化。
//
// inputNames 是所有输入节点名,output 是实际输出了的节点名。节点名与组名重名时按组处理
// (组还在就不是悬空)。
func prunePolicyGroups(groups []policyGroupMembers, inputNames []string, output map[string]bool) *policyPruneResult {
	groupNames := make(map[string]bool, len(groups))
	for _, g := range groups {
		groupNames[g.Name] = true
	}
	res := &policyPruneResult{
		Members: make([][]string, len(groups)),
		Removed: make(map[string]bool),
		dropped: make(map[string]bool),
	}
	for _, name := range inputNames {
		if name != "" && !output[name] && !groupNames[name] {
			res.dropped[name] = true
		}
	}
	for i, g := range groups {
		res.Members[i] = g.Members
	}
	if len(res.dropped) == 0 {
		return res
	}

	for changed := true; changed; {
		changed = false
		for i, g := range groups {
			if res.Removed[g.Name] || len(res.Members[i]) == 0 {
				continue
			}
			kept := make([]string, 0, len(res.Members[i]))
			for _, m := range res.Members[i] {
				if !res.Dangling(m) {
					kept = append(kept, m)
				}
			}
			if len(kept) == len(res.Members[i]) {
				continue
			}
			res.Members[i] = kept
			changed = true
			if len(kept) == 0 {
				res.Removed[g.Name] = true
			}
		}
	}
	return res
}

// rewriteDanglingRulePolicy 把目标策略悬空的规则改成 DIRECT(目标组被删、或直接指向没输出的节点)。
// 规则格式 TYPE,VALUE,POLICY[,选项...];FINAL / MATCH 没有 VALUE。逻辑规则
// (AND,((DOMAIN,a),(DST-PORT,443)),POLICY)括号里的逗号不算分隔符。注释行原样返回。
func rewriteDanglingRulePolicy(rule string, dangling func(string) bool) string {
	trimmed := strings.TrimSpace(rule)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return rule
	}
	parts := splitRuleTopLevel(rule)
	idx := 2
	switch strings.ToUpper(strings.TrimSpace(parts[0])) {
	case "FINAL", "MATCH":
		idx = 1
	}
	if len(parts) <= idx || !dangling(parts[idx]) {
		return rule
	}
	parts[idx] = "DIRECT"
	return strings.Join(parts, ",")
}

// splitRuleTopLevel 按不在括号里的逗号切分规则。
func splitRuleTopLevel(rule string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(rule); i++ {
		switch rule[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, rule[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, rule[start:])
}
