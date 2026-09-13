package substore

import (
	"regexp"
	"strings"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/logger"

	"gopkg.in/yaml.v3"
)

// RegionProxyGroup defines a predefined region proxy group
type RegionProxyGroup struct {
	Name   string
	Filter string
}

// OtherRegionsGroupName 是「其他地区」组的组名。
// 它不在 RegionProxyGroups 里:该组不是靠 filter 命中，而是靠 exclude-filter 把上面
// 所有地区排掉，见 insertRegionProxyGroups / GetOtherRegionsExcludeFilter。
const OtherRegionsGroupName = "🌐 其他地区"

// Predefined region proxy groups
//
// 注意：这里只放「靠 filter 正着命中」的地区。以前末尾还挂着一条
// {Name: "🌐 其他地区", Filter: "(^(?!.*(全部地区关键词)).*)"}，有两个害处：
//  1. insertRegionProxyGroups 遍历完本表后还会再单独建一个「🌐 其他地区」，产出重名组；
//  2. 那条 filter 用了负向先行断言，RE2 编译不了，还会被 GetOtherRegionsExcludeFilter
//     拼进「其他地区」的 exclude-filter 里，把整条 exclude 也带成编译失败
//     （结果就是「其他地区」要么空掉被删、要么一个节点都排不掉）。
var RegionProxyGroups = []RegionProxyGroup{
	{Name: "🇭🇰 香港节点", Filter: `🇭🇰|港|\bHK(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|hk|Hong Kong|HongKong|hongkong|HONG KONG|HONGKONG|深港|HKG|九龙|Kowloon|新界|沙田|荃湾|葵涌`},
	{Name: "🇺🇸 美国节点", Filter: `🇺🇸|美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|纽约|纽纽|亚特兰大|迈阿密|华盛顿|\bUS(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|United States|UnitedStates|UNITED STATES|USA|America|AMERICA|JFK|EWR|IAD|ATL|ORD|MIA|NYC|LAX|SFO|SEA|DFW|SJC`},
	{Name: "🇯🇵 日本节点", Filter: `🇯🇵|日本|川日|东京|大阪|泉日|埼玉|沪日|深日|(?<!尼|-)日|\bJP(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|Japan|JAPAN|JPN|NRT|HND|KIX|TYO|OSA|关西|Kansai|KANSAI`},
	{Name: "🇸🇬 新加坡节点", Filter: `🇸🇬|新加坡|坡|狮城|\bSG(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|Singapore|SINGAPORE|SIN`},
	{Name: "🇼🇸 台湾节点", Filter: `🇹🇼|🇼🇸|台|新北|彰化|\bTW(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|Taiwan|TAIWAN|TWN|TPE|ROC`},
	{Name: "🇰🇷 韩国节点", Filter: `🇰🇷|\bKR(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|Korea|KOREA|KOR|首尔|韩|韓|春川|Chuncheon|ICN`},
	{Name: "🇨🇦 加拿大节点", Filter: `🇨🇦|加拿大|\bCA(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|Canada|CANADA|CAN|渥太华|温哥华|卡尔加里|蒙特利尔|Montreal|YVR|YYZ|YUL`},
	{Name: "🇬🇧 英国节点", Filter: `🇬🇧|英国|Britain|United Kingdom|UNITED KINGDOM|England|伦敦|曼彻斯特|Manchester|\bUK(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|GBR|LHR|MAN`},
	{Name: "🇫🇷 法国节点", Filter: `🇫🇷|法国|\bFR(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|France|FRANCE|FRA|巴黎|马赛|Marseille|CDG|MRS`},
	{Name: "🇩🇪 德国节点", Filter: `🇩🇪|德国|Germany|GERMANY|\bDE(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|DEU|柏林|法兰克福|慕尼黑|Munich|MUC`},
	{Name: "🇳🇱 荷兰节点", Filter: `🇳🇱|荷兰|Netherlands|NETHERLANDS|\bNL(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|NLD|阿姆斯特丹|AMS`},
	{Name: "🇹🇷 土耳其节点", Filter: `🇹🇷|土耳其|Turkey|TURKEY|Türkiye|\bTR(?:[-_ ]?\d+(?:[-_ ]?[A-Za-z]{2,})?)?\b|TUR|IST|ANK`},
}

// Special markers for proxy order
const (
	ProxyNodesMarker        = "__PROXY_NODES__"
	ProxyProvidersMarker    = "__PROXY_PROVIDERS__"
	RegionProxyGroupsMarker = "__REGION_PROXY_GROUPS__"
)

// GetOtherRegionsExcludeFilter returns the exclude filter for "Other regions" group
func GetOtherRegionsExcludeFilter() string {
	var filters []string
	for _, r := range RegionProxyGroups {
		filters = append(filters, r.Filter)
	}
	return strings.Join(filters, "|")
}

// GetRegionProxyGroupNames returns all region proxy group names including "Other regions"
func GetRegionProxyGroupNames() []string {
	names := make([]string, 0, len(RegionProxyGroups)+1)
	for _, r := range RegionProxyGroups {
		names = append(names, r.Name)
	}
	names = append(names, OtherRegionsGroupName)
	return names
}

// AdapterType represents the type of proxy adapter (matching mihomo's definition)
type AdapterType string

const (
	AdapterDirect       AdapterType = "direct"
	AdapterReject       AdapterType = "reject"
	AdapterRejectDrop   AdapterType = "reject-drop"
	AdapterCompatible   AdapterType = "compatible"
	AdapterPass         AdapterType = "pass"
	AdapterDns          AdapterType = "dns"
	AdapterRelay        AdapterType = "relay"
	AdapterSelector     AdapterType = "select"
	AdapterFallback     AdapterType = "fallback"
	AdapterURLTest      AdapterType = "url-test"
	AdapterLoadBalance  AdapterType = "load-balance"
	AdapterShadowsocks  AdapterType = "ss"
	AdapterShadowsocksR AdapterType = "ssr"
	AdapterSnell        AdapterType = "snell"
	AdapterSocks5       AdapterType = "socks5"
	AdapterHttp         AdapterType = "http"
	AdapterVmess        AdapterType = "vmess"
	AdapterVless        AdapterType = "vless"
	AdapterTrojan       AdapterType = "trojan"
	AdapterHysteria     AdapterType = "hysteria"
	AdapterHysteria2    AdapterType = "hysteria2"
	AdapterWireGuard    AdapterType = "wireguard"
	AdapterTuic         AdapterType = "tuic"
	AdapterSsh          AdapterType = "ssh"
	AdapterAnytls       AdapterType = "anytls"
)

// ProxyGroupV3 represents a proxy group with mihomo-style include/filter options
type ProxyGroupV3 struct {
	Name                     string   `yaml:"name"`
	Type                     string   `yaml:"type"`
	Proxies                  []string `yaml:"proxies,omitempty"`
	Use                      []string `yaml:"use,omitempty"`                         // 引入代理集合
	IncludeAll               bool     `yaml:"include-all,omitempty"`                 // 引入所有出站代理和代理集合
	IncludeType              string   `yaml:"include-type,omitempty"`                // 根据节点类型引入节点
	IncludeAllProxies        bool     `yaml:"include-all-proxies,omitempty"`         // 引入所有出站代理
	IncludeAllProviders      bool     `yaml:"include-all-providers,omitempty"`       // 引入所有代理集合
	IncludeRegionProxyGroups bool     `yaml:"include-region-proxy-groups,omitempty"` // 引入地区代理组
	Filter                   string   `yaml:"filter,omitempty"`                      // 筛选节点的正则表达式
	ExcludeFilter            string   `yaml:"exclude-filter,omitempty"`              // 排除节点的正则表达式
	ExcludeType              string   `yaml:"exclude-type,omitempty"`                // 根据类型排除节点
	URL                      string   `yaml:"url,omitempty"`
	Interval                 int      `yaml:"interval,omitempty"`
	Tolerance                int      `yaml:"tolerance,omitempty"`
	Lazy                     bool     `yaml:"lazy,omitempty"`
	DisableUDP               bool     `yaml:"disable-udp,omitempty"`
	Strategy                 string   `yaml:"strategy,omitempty"`
	InterfaceName            string   `yaml:"interface-name,omitempty"`
	RoutingMark              int      `yaml:"routing-mark,omitempty"`
}

// ProxyNode represents a proxy node with its type
type ProxyNode struct {
	Name string
	Type string
}

// TemplateV3Processor processes v3 templates with mihomo-style proxy group options
type TemplateV3Processor struct {
	allProxies        []ProxyNode         // All available proxy nodes
	proxyGroups       []string            // Names of proxy groups (for reference)
	providers         map[string][]string // Provider name -> proxy names
	regionGroupsAdded bool                // Whether region proxy groups have been added
	regionGroupNames  []string            // Names of region proxy groups
	variables         map[string]string   // 模板自定义变量（非标准顶级键）
	usedVariables     map[string]bool     // 被实际引用的变量
}

// Clash/mihomo 标准顶级键（不视为自定义变量）
var standardTopLevelKeys = map[string]bool{
	"port": true, "socks-port": true, "redir-port": true, "tproxy-port": true,
	"mixed-port": true, "allow-lan": true, "bind-address": true, "mode": true,
	"log-level": true, "external-controller": true, "external-ui": true,
	"ipv6": true, "dns": true, "proxies": true, "proxy-groups": true,
	"proxy-providers": true, "rules": true, "rule-providers": true,
	"hosts": true, "profile": true, "tun": true, "sniffer": true,
	"authentication": true, "unified-delay": true, "tcp-concurrent": true,
	"find-process-mode": true, "global-client-fingerprint": true,
	"keep-alive-interval": true, "geodata-mode": true, "geo-auto-update": true,
	"geo-update-interval": true, "geox-url": true,
	"add-region-proxy-groups": true, // MMW 自定义字段
}

// NewTemplateV3Processor creates a new v3 template processor
func NewTemplateV3Processor(proxies []ProxyNode, providers map[string][]string) *TemplateV3Processor {
	return &TemplateV3Processor{
		allProxies:        proxies,
		providers:         providers,
		proxyGroups:       []string{},
		regionGroupsAdded: false,
		regionGroupNames:  GetRegionProxyGroupNames(),
		variables:         make(map[string]string),
		usedVariables:     make(map[string]bool),
	}
}

// ExtractTemplateVariables 从模板 YAML 中提取自定义变量（非 Clash 标准顶级键的标量值）
func ExtractTemplateVariables(content string) map[string]string {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return nil
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	rootMap := root.Content[0]
	if rootMap.Kind != yaml.MappingNode {
		return nil
	}
	return collectVariables(rootMap)
}

// collectVariables 从 YAML 根映射中收集自定义变量（非标准键且值为标量字符串）
func collectVariables(rootMap *yaml.Node) map[string]string {
	vars := make(map[string]string)
	for i := 0; i < len(rootMap.Content)-1; i += 2 {
		key := rootMap.Content[i].Value
		val := rootMap.Content[i+1]
		// 仅收集非标准键且值为标量字符串的条目
		if !standardTopLevelKeys[key] && val.Kind == yaml.ScalarNode && val.Tag == "!!str" {
			vars[key] = val.Value
		}
	}
	return vars
}

// ProcessTemplate processes a v3 template and expands proxy groups
func (p *TemplateV3Processor) ProcessTemplate(templateContent string, proxies []map[string]any) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(templateContent), &root); err != nil {
		return "", err
	}

	// Extract proxy nodes from the provided proxies
	p.allProxies = extractProxyNodes(proxies)

	// Track which proxy nodes are used (for adding to top-level proxies)
	usedProxyNames := make(map[string]bool)

	// Find and process proxy-groups
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		rootMap := root.Content[0]
		if rootMap.Kind == yaml.MappingNode {
			// 收集模板自定义变量（非标准顶级键的标量值）
			p.variables = collectVariables(rootMap)
			if len(p.variables) > 0 {
				for name, value := range p.variables {
					logger.Info("[模板变量] 发现自定义变量", "name", name, "value", value)
				}
			}

			var proxyGroupsIndex int = -1
			var addRegionProxyGroups bool = false

			// First pass: find proxy-groups and check for add-region-proxy-groups
			for i := 0; i < len(rootMap.Content); i += 2 {
				keyNode := rootMap.Content[i]
				valueNode := rootMap.Content[i+1]

				if keyNode.Value == "add-region-proxy-groups" {
					addRegionProxyGroups = valueNode.Value == "true"
				}
				if keyNode.Value == "proxy-groups" && valueNode.Kind == yaml.SequenceNode {
					proxyGroupsIndex = i + 1
				}
			}

			// Process proxy-groups if found
			if proxyGroupsIndex >= 0 {
				valueNode := rootMap.Content[proxyGroupsIndex]

				// 先把 YAML 别名/合并键摊平成普通 mapping。必须赶在下面这些
				// collect*/has* 之前做：它们（以及 processProxyGroups）都只认 MappingNode，
				// 遇到 `- *anchor` 会连组名都收不到，整组无声蒸发。
				p.normalizeGroupEntries(valueNode)

				// Check if any proxy group has include-region-proxy-groups: true or __REGION_PROXY_GROUPS__ marker
				if !addRegionProxyGroups {
					addRegionProxyGroups = p.hasIncludeRegionProxyGroups(valueNode) || p.hasRegionProxyGroupsMarker(valueNode)
				}

				// If add-region-proxy-groups is true or any group has include-region-proxy-groups, insert region groups
				if addRegionProxyGroups {
					p.insertRegionProxyGroups(valueNode)
				}

				// Collect all proxy group names (including newly added region groups)
				p.collectProxyGroupNames(valueNode)

				// Collect dialer-proxy-group field mapping before processing (removeMihomoFields will strip them)
				dpGroupMap := p.collectDialerProxyGroupMap(valueNode)

				// Process each proxy group
				if err := p.processProxyGroups(valueNode); err != nil {
					return "", err
				}

				// Collect used proxy names from processed proxy-groups
				usedProxyNames = p.collectUsedProxyNames(valueNode)

				// Build dialer proxy configs using processed proxy-groups (proxies now expanded)
				dpConfigs := p.buildDialerProxyConfigs(valueNode, dpGroupMap)

				// Add or update top-level proxies with used proxy configs
				p.updateTopLevelProxies(rootMap, proxies, usedProxyNames, dpConfigs)
			}

			// Remove add-region-proxy-groups from output
			p.removeGlobalConfig(rootMap, "add-region-proxy-groups")

			// 只移除被实际引用的变量键（未引用的保留为全局配置）
			for name := range p.usedVariables {
				p.removeGlobalConfig(rootMap, name)
			}
		}
	}

	// Marshal back to YAML
	var buf strings.Builder
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return "", err
	}
	encoder.Close()

	// Post-process to convert Unicode escape sequences back to original characters
	result := unescapeUnicode(buf.String())
	return result, nil
}

// collectProxyGroupNames collects all proxy group names for reference
func (p *TemplateV3Processor) collectProxyGroupNames(groupsNode *yaml.Node) {
	p.proxyGroups = []string{}
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind == yaml.MappingNode {
			for i := 0; i < len(groupNode.Content); i += 2 {
				if groupNode.Content[i].Value == "name" {
					p.proxyGroups = append(p.proxyGroups, groupNode.Content[i+1].Value)
					break
				}
			}
		}
	}
}

// hasIncludeRegionProxyGroups checks if any proxy group has include-region-proxy-groups: true
func (p *TemplateV3Processor) hasIncludeRegionProxyGroups(groupsNode *yaml.Node) bool {
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind == yaml.MappingNode {
			for i := 0; i < len(groupNode.Content); i += 2 {
				if groupNode.Content[i].Value == "include-region-proxy-groups" {
					if groupNode.Content[i+1].Value == "true" {
						return true
					}
				}
			}
		}
	}
	return false
}

// hasRegionProxyGroupsMarker checks if any proxy group's proxies list contains __REGION_PROXY_GROUPS__ marker
func (p *TemplateV3Processor) hasRegionProxyGroupsMarker(groupsNode *yaml.Node) bool {
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind == yaml.MappingNode {
			for i := 0; i < len(groupNode.Content); i += 2 {
				if groupNode.Content[i].Value == "proxies" {
					proxiesNode := groupNode.Content[i+1]
					if proxiesNode.Kind == yaml.SequenceNode {
						for _, item := range proxiesNode.Content {
							if item.Value == RegionProxyGroupsMarker {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// insertRegionProxyGroups inserts predefined region proxy groups at the beginning
func (p *TemplateV3Processor) insertRegionProxyGroups(groupsNode *yaml.Node) {
	if p.regionGroupsAdded {
		return
	}

	var newGroups []*yaml.Node

	// Create region proxy groups
	for _, region := range RegionProxyGroups {
		groupNode := p.createRegionGroupNode(region.Name, region.Filter, "")
		newGroups = append(newGroups, groupNode)
	}

	// Create "Other regions" group with exclude filter
	otherRegionNode := p.createRegionGroupNode(OtherRegionsGroupName, "", GetOtherRegionsExcludeFilter())
	newGroups = append(newGroups, otherRegionNode)

	// Prepend new groups to existing groups
	groupsNode.Content = append(newGroups, groupsNode.Content...)
	p.regionGroupsAdded = true
}

// createRegionGroupNode creates a YAML node for a region proxy group
func (p *TemplateV3Processor) createRegionGroupNode(name, filter, excludeFilter string) *yaml.Node {
	groupNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}

	// Add name
	groupNode.Content = append(groupNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: name},
	)

	// Add type (url-test)
	groupNode.Content = append(groupNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "type"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "url-test"},
	)

	// Add include-all-proxies
	groupNode.Content = append(groupNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "include-all-proxies"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"},
	)

	// Add filter or exclude-filter
	if filter != "" {
		groupNode.Content = append(groupNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "filter"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: filter},
		)
	}
	if excludeFilter != "" {
		groupNode.Content = append(groupNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "exclude-filter"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: excludeFilter},
		)
	}

	// Add url-test options
	groupNode.Content = append(groupNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "url"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "https://cp.cloudflare.com/generate_204"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "interval"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "300"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tolerance"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "50"},
	)

	return groupNode
}

// removeGlobalConfig removes a global config key from the root map
func (p *TemplateV3Processor) removeGlobalConfig(rootMap *yaml.Node, key string) {
	newContent := make([]*yaml.Node, 0, len(rootMap.Content))
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value != key {
			newContent = append(newContent, rootMap.Content[i], rootMap.Content[i+1])
		}
	}
	rootMap.Content = newContent
}

// normalizeGroupEntries 把 proxy-groups 里的每一条摊平成独立的 MappingNode：
//   - `- *anchor`（整条是别名）→ 深拷贝锚点内容；
//   - `<<: *anchor`（合并键）→ 就地展开成普通键值对。
//
// yaml.v3 只有在 Decode 进 struct/map 时才会处理这两种写法，我们全程操作 yaml.Node，
// 不摊平就等于看不见锚点里的 name/type/proxies——组要么无声蒸发、要么被当成空组删掉。
// 摊平的是拷贝，不动锚点本身（锚点可能还被别处引用），并清掉 Anchor 防止输出里出现重复锚点。
func (p *TemplateV3Processor) normalizeGroupEntries(groupsNode *yaml.Node) {
	if groupsNode == nil || groupsNode.Kind != yaml.SequenceNode {
		return
	}
	for i, entry := range groupsNode.Content {
		node := entry
		if node.Kind == yaml.AliasNode {
			target := derefAliasNode(node)
			if target == nil || target.Kind != yaml.MappingNode {
				// 解不了的别名（锚点缺失/不是 mapping）：原样留着并记日志，
				// 至少不会让这一条凭空消失。
				logger.Warn("[模板V3] proxy-groups 里有解不开的 YAML 别名，原样保留", "alias", node.Value)
				continue
			}
			node = deepCopyYAMLNode(target)
			node.Anchor = ""
			logger.Info("[模板V3] proxy-groups 条目是 YAML 别名，已展开", "alias", entry.Value)
		}
		if node.Kind != yaml.MappingNode {
			logger.Warn("[模板V3] proxy-groups 里有非 mapping 条目，原样保留", "kind", int(node.Kind))
			continue
		}
		expandMergeKeys(node)
		groupsNode.Content[i] = node
	}
}

// derefAliasNode 顺着别名链找到真正的目标节点（别名指向别名的情况很少见，但不花钱）。
func derefAliasNode(node *yaml.Node) *yaml.Node {
	n := node
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 10; i++ {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

// deepCopyYAMLNode 深拷贝一个 yaml 节点（锚点名清空由调用方决定）。
func deepCopyYAMLNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Content = make([]*yaml.Node, 0, len(n.Content))
	for _, child := range n.Content {
		c.Content = append(c.Content, deepCopyYAMLNode(child))
	}
	return &c
}

// expandMergeKeys 就地展开 mapping 里的 `<<` 合并键。
// 按 YAML 规范：本条目自己显式写的键优先，多个合并源之间先出现的优先。
func expandMergeKeys(mapping *yaml.Node) {
	hasMerge := false
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "<<" {
			hasMerge = true
			break
		}
	}
	if !hasMerge {
		return
	}

	seen := make(map[string]bool)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if key := mapping.Content[i].Value; key != "<<" {
			seen[key] = true
		}
	}

	var kept, merged []*yaml.Node
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if key.Value != "<<" {
			kept = append(kept, key, value)
			continue
		}
		for _, src := range mergeSources(value) {
			for j := 0; j+1 < len(src.Content); j += 2 {
				name := src.Content[j].Value
				if seen[name] {
					continue
				}
				seen[name] = true
				mk := deepCopyYAMLNode(src.Content[j])
				mv := deepCopyYAMLNode(src.Content[j+1])
				mk.Anchor, mv.Anchor = "", ""
				merged = append(merged, mk, mv)
			}
		}
	}
	mapping.Content = append(kept, merged...)
}

// mergeSources 解析 `<<` 的值：可以是别名、行内 mapping，或它们组成的序列。
func mergeSources(value *yaml.Node) []*yaml.Node {
	switch value.Kind {
	case yaml.AliasNode:
		if target := derefAliasNode(value); target != nil && target.Kind == yaml.MappingNode {
			return []*yaml.Node{target}
		}
		logger.Warn("[模板V3] 合并键 << 指向的锚点解不开，已跳过", "alias", value.Value)
	case yaml.MappingNode:
		return []*yaml.Node{value}
	case yaml.SequenceNode:
		var sources []*yaml.Node
		for _, item := range value.Content {
			sources = append(sources, mergeSources(item)...)
		}
		return sources
	}
	return nil
}

// processProxyGroups processes all proxy groups in the template
func (p *TemplateV3Processor) processProxyGroups(groupsNode *yaml.Node) error {
	var newContent []*yaml.Node
	removedGroups := make(map[string]bool)

	// First pass: process each proxy group and identify empty ones
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			// normalizeGroupEntries 已经尽力摊平过了，走到这里说明这条既不是 mapping
			// 也解不成 mapping。原样带出去交给客户端判断，总好过静默吞掉一整条。
			newContent = append(newContent, groupNode)
			continue
		}
		if err := p.processProxyGroup(groupNode); err != nil {
			return err
		}
		// Check if proxies is empty after processing
		if p.hasEmptyProxies(groupNode) {
			// Record the removed group name
			for i := 0; i < len(groupNode.Content); i += 2 {
				if groupNode.Content[i].Value == "name" {
					name := groupNode.Content[i+1].Value
					removedGroups[name] = true
					logger.Info("[模板V3] 代理组成员为空，已删除", "group", name)
					break
				}
			}
		} else {
			newContent = append(newContent, groupNode)
		}
	}

	// Second pass: remove references to removed groups from remaining groups
	if len(removedGroups) > 0 {
		for _, groupNode := range newContent {
			p.removeGroupReferences(groupNode, removedGroups)
			// 删引用可能把组掏空。`proxies: []` 会让 mihomo/Loon 直接拒载整份配置，
			// 所以这里不再复查一遍"空了就删"（那会连锁删组、把 rules 指向的策略也删没），
			// 而是塞一个 DIRECT 兜底——跟 Loon 转换层同一个约定：组还在，规则还能解析。
			p.ensureNonEmptyProxies(groupNode)
		}
		// Update proxy group names list
		p.proxyGroups = p.filterProxyGroupNames(p.proxyGroups, removedGroups)
	}

	groupsNode.Content = newContent
	return nil
}

// ensureNonEmptyProxies 保证组的 proxies 至少有一个成员（空则补 DIRECT）。
func (p *TemplateV3Processor) ensureNonEmptyProxies(groupNode *yaml.Node) {
	if groupNode.Kind != yaml.MappingNode {
		return
	}
	var name string
	for i := 0; i+1 < len(groupNode.Content); i += 2 {
		if groupNode.Content[i].Value == "name" {
			name = groupNode.Content[i+1].Value
			break
		}
	}
	for i := 0; i+1 < len(groupNode.Content); i += 2 {
		if groupNode.Content[i].Value != "proxies" {
			continue
		}
		proxiesNode := groupNode.Content[i+1]
		if proxiesNode.Kind == yaml.SequenceNode && len(proxiesNode.Content) == 0 {
			proxiesNode.Content = append(proxiesNode.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: "DIRECT",
			})
			logger.Warn("[模板V3] 代理组引用的组都被删了，补 DIRECT 兜底以免产出 proxies: []", "group", name)
		}
		return
	}
}

// removeGroupReferences removes references to removed groups from a proxy group's proxies list
func (p *TemplateV3Processor) removeGroupReferences(groupNode *yaml.Node, removedGroups map[string]bool) {
	for i := 0; i < len(groupNode.Content); i += 2 {
		if groupNode.Content[i].Value == "proxies" {
			proxiesNode := groupNode.Content[i+1]
			if proxiesNode.Kind == yaml.SequenceNode {
				var newProxies []*yaml.Node
				for _, proxyNode := range proxiesNode.Content {
					if !removedGroups[proxyNode.Value] {
						newProxies = append(newProxies, proxyNode)
					}
				}
				proxiesNode.Content = newProxies
			}
			break
		}
	}
}

// filterProxyGroupNames filters out removed group names from the list
func (p *TemplateV3Processor) filterProxyGroupNames(names []string, removedGroups map[string]bool) []string {
	var result []string
	for _, name := range names {
		if !removedGroups[name] {
			result = append(result, name)
		}
	}
	return result
}

// hasEmptyProxies checks if a proxy group has empty or no proxies
//
// 只在 processProxyGroup 之后调用，那时 updateProxiesInNode 一定已经写好了 proxies 键
// （有成员写成员、没成员写空序列），所以"判空"实际只看空序列这一种情况。
// 没有 proxies 键 = 这个组根本没被处理过（比如以后有人挪了调用顺序），
// 这种情况按 mihomo 语义（只写 use:/include-all 的组是合法的）保留，不能当空组删——
// 删组的代价是 rules 里指向它的规则全成悬空引用，比多留一个组严重得多。
func (p *TemplateV3Processor) hasEmptyProxies(groupNode *yaml.Node) bool {
	for i := 0; i < len(groupNode.Content); i += 2 {
		if groupNode.Content[i].Value == "proxies" {
			valueNode := groupNode.Content[i+1]
			return valueNode.Kind == yaml.SequenceNode && len(valueNode.Content) == 0
		}
	}
	return false
}

// processProxyGroup processes a single proxy group
func (p *TemplateV3Processor) processProxyGroup(groupNode *yaml.Node) error {
	group := p.parseProxyGroup(groupNode)

	// Calculate the final proxy list
	finalProxies := p.calculateProxies(group)

	// Update the proxies field in the YAML node
	p.updateProxiesInNode(groupNode, finalProxies)

	// Remove mihomo-specific fields that we've processed
	p.removeMihomoFields(groupNode)

	return nil
}

// parseProxyGroup parses a proxy group from YAML node
func (p *TemplateV3Processor) parseProxyGroup(groupNode *yaml.Node) ProxyGroupV3 {
	var group ProxyGroupV3

	for i := 0; i < len(groupNode.Content); i += 2 {
		key := groupNode.Content[i].Value
		// 值也可能是别名（`proxies: *common_nodes`）。不解引用的话别名节点的 Value
		// 是锚点名、Content 是空的，组就会被算成"没有成员"而删掉。
		valueNode := groupNode.Content[i+1]
		if valueNode.Kind == yaml.AliasNode {
			if target := derefAliasNode(valueNode); target != nil {
				valueNode = target
			}
		}

		switch key {
		case "name":
			group.Name = valueNode.Value
		case "type":
			group.Type = valueNode.Value
		case "proxies":
			if valueNode.Kind == yaml.SequenceNode {
				for _, item := range valueNode.Content {
					group.Proxies = append(group.Proxies, item.Value)
				}
			}
		case "use":
			if valueNode.Kind == yaml.SequenceNode {
				for _, item := range valueNode.Content {
					group.Use = append(group.Use, item.Value)
				}
			}
		case "include-all":
			group.IncludeAll = valueNode.Value == "true"
		case "include-type":
			group.IncludeType = valueNode.Value
		case "include-all-proxies":
			group.IncludeAllProxies = valueNode.Value == "true"
		case "include-all-providers":
			group.IncludeAllProviders = valueNode.Value == "true"
		case "include-region-proxy-groups":
			group.IncludeRegionProxyGroups = valueNode.Value == "true"
		case "filter":
			group.Filter = valueNode.Value
			// 解析变量引用：filter 值如果是自定义变量名，替换为变量值
			if resolved, ok := p.variables[group.Filter]; ok {
				logger.Info("[模板变量] 代理组 filter 引用变量已解析", "group", group.Name, "variable", group.Filter, "resolved", resolved)
				p.usedVariables[group.Filter] = true
				group.Filter = resolved
			}
		case "exclude-filter":
			group.ExcludeFilter = valueNode.Value
			// 解析变量引用
			if resolved, ok := p.variables[group.ExcludeFilter]; ok {
				logger.Info("[模板变量] 代理组 exclude-filter 引用变量已解析", "group", group.Name, "variable", group.ExcludeFilter, "resolved", resolved)
				p.usedVariables[group.ExcludeFilter] = true
				group.ExcludeFilter = resolved
			}
		case "exclude-type":
			group.ExcludeType = valueNode.Value
		case "url":
			group.URL = valueNode.Value
		case "interval":
			// Parse int from string
			if valueNode.Tag == "!!int" {
				group.Interval = parseInt(valueNode.Value)
			}
		case "tolerance":
			if valueNode.Tag == "!!int" {
				group.Tolerance = parseInt(valueNode.Value)
			}
		}
	}

	return group
}

// calculateProxies calculates the final proxy list based on include/filter options
func (p *TemplateV3Processor) calculateProxies(group ProxyGroupV3) []string {
	var result []string

	// Calculate proxy nodes (from include-all-proxies, include-type, filter)
	proxyNodes := p.calculateProxyNodes(group)

	// Calculate proxy providers (from use, include-all-providers)
	proxyProviders, providersRequested, missingProviders := p.calculateProxyProviders(group)

	// 假空兜底：主控侧 5 个调用点（subscription.go / packages.go / template_v3.go /
	// package_subscribe.go ×2）全都是 NewTemplateV3Processor(nil, nil)，providers 恒为 nil，
	// 模板里的 proxy-providers 从来没被读进来过。于是「只靠 use: / include-all-providers
	// 取成员」的组会一个成员都凑不出来，随后被当空组删掉——组一没，rules 里指向它的规则
	// 就成了悬空引用。这里在"声明了要用代理集合、却连一个成员都凑不出来"时退回当前节点池，
	// 让组保持可用（filter/exclude-filter 随后照常生效）。
	// 只在真的凑不出成员时才兜底：组里本来就有显式成员或节点的，一个都不多给。
	if providersRequested && len(proxyProviders) == 0 && len(proxyNodes) == 0 && !hasExplicitMembers(group.Proxies) {
		for _, proxy := range p.allProxies {
			proxyProviders = append(proxyProviders, proxy.Name)
		}
		logger.Warn("[模板V3] 代理集合(proxy-providers)解析不到，已用当前节点池兜底以免整组消失",
			"group", group.Name, "use", strings.Join(group.Use, ","),
			"missing", strings.Join(missingProviders, ","), "fallback", len(proxyProviders))
	}

	// Check if proxies list contains markers
	hasNodesMarker := false
	hasProvidersMarker := false
	hasRegionGroupsMarker := false
	for _, proxy := range group.Proxies {
		if proxy == ProxyNodesMarker {
			hasNodesMarker = true
		}
		if proxy == ProxyProvidersMarker {
			hasProvidersMarker = true
		}
		if proxy == RegionProxyGroupsMarker {
			hasRegionGroupsMarker = true
		}
	}

	// If markers are present, use them to determine order
	if hasNodesMarker || hasProvidersMarker || hasRegionGroupsMarker {
		for _, proxy := range group.Proxies {
			if proxy == ProxyNodesMarker {
				result = append(result, proxyNodes...)
			} else if proxy == ProxyProvidersMarker {
				result = append(result, proxyProviders...)
			} else if proxy == RegionProxyGroupsMarker {
				result = append(result, p.regionGroupNames...)
			} else {
				result = append(result, proxy)
			}
		}
	} else {
		// No markers, use default order: region groups (if enabled), proxies, then nodes, then providers
		if group.IncludeRegionProxyGroups {
			result = append(result, p.regionGroupNames...)
		}
		result = append(result, group.Proxies...)
		result = append(result, proxyNodes...)
		result = append(result, proxyProviders...)
	}

	// Apply filter (include matching) - only to proxy nodes, not to proxy groups
	if group.Filter != "" {
		result = applyFilterPreservingGroups(group.Name, result, group.Filter, p.proxyGroups)
	}

	// Apply exclude-filter (exclude matching)
	if group.ExcludeFilter != "" {
		result = applyExcludeFilterForGroup(group.Name, result, group.ExcludeFilter)
	}

	// Apply exclude-type
	if group.ExcludeType != "" {
		excludeTypes := parseTypeList(group.ExcludeType)
		result = p.excludeByType(result, excludeTypes)
	}

	// Remove duplicates while preserving order
	result = removeDuplicates(result)

	return result
}

// calculateProxyNodes calculates proxy nodes from include options
func (p *TemplateV3Processor) calculateProxyNodes(group ProxyGroupV3) []string {
	var nodes []string

	// 检查 proxies 列表中是否包含 __PROXY_NODES__ 占位符，等同于 include-all-proxies
	hasNodesMarker := false
	for _, proxy := range group.Proxies {
		if proxy == ProxyNodesMarker {
			hasNodesMarker = true
			break
		}
	}

	// Check if explicit include option is set (not counting filter as include)
	hasExplicitInclude := group.IncludeAll || group.IncludeAllProxies || group.IncludeType != "" || hasNodesMarker

	if group.IncludeAll || group.IncludeAllProxies || hasNodesMarker {
		for _, proxy := range p.allProxies {
			nodes = append(nodes, proxy.Name)
		}
	} else if group.IncludeType != "" {
		types := parseTypeList(group.IncludeType)
		for _, proxy := range p.allProxies {
			if containsType(types, proxy.Type) {
				nodes = append(nodes, proxy.Name)
			}
		}
	} else if !hasExplicitInclude && (group.Filter != "" || group.ExcludeFilter != "") {
		// If no explicit include option is set but filter/exclude-filter is present,
		// implicitly include all proxies (mihomo behavior)
		for _, proxy := range p.allProxies {
			nodes = append(nodes, proxy.Name)
		}
	}

	return nodes
}

// calculateProxyProviders calculates proxy providers from include options
//
// 返回值：解析出来的成员、是否声明过要用代理集合、以及哪些集合名没解析到。
// 后两个给 calculateProxies 判"要不要走假空兜底"用。
func (p *TemplateV3Processor) calculateProxyProviders(group ProxyGroupV3) (providers []string, requested bool, missing []string) {
	if group.IncludeAll || group.IncludeAllProviders {
		requested = true
		for _, providerProxies := range p.providers {
			providers = append(providers, providerProxies...)
		}
	} else if len(group.Use) > 0 {
		requested = true
		for _, providerName := range group.Use {
			if providerProxies, ok := p.providers[providerName]; ok {
				providers = append(providers, providerProxies...)
			} else {
				missing = append(missing, providerName)
			}
		}
	}

	return providers, requested, missing
}

// hasExplicitMembers 判断 proxies 里除了占位符之外还有没有真成员
func hasExplicitMembers(proxies []string) bool {
	for _, name := range proxies {
		switch name {
		case ProxyNodesMarker, ProxyProvidersMarker, RegionProxyGroupsMarker, "":
			continue
		}
		return true
	}
	return false
}

// groupPatternMatcher 是 filter / exclude-filter 里**单条**正则编译出来的匹配器。
//
// 为什么要包一层：模板作者写的是 mihomo 那套正则（支持先行/后行断言），而 Go 用的是
// RE2，(?=...) / (?!...) 一律编译失败。老代码在编译失败时直接 `err == nil && matched`
// 吞掉错误，等价于"这条正则谁都匹配不上"——放在 filter 上就是**全员淘汰**，整个代理组
// 成员为空，紧接着被 processProxyGroups 当空组删掉（用户 44 个组只剩 25 个的头号成因）。
type groupPatternMatcher struct {
	re     *regexp.Regexp // nil 表示恒定结果（编译失败后的降级）
	negate bool           // 由负向先行断言改写而来：命中 re 反而意味着"不匹配"
	fixed  bool           // re == nil 时的恒定返回值
}

func (m groupPatternMatcher) match(name string) bool {
	if m.re == nil {
		return m.fixed
	}
	if m.negate {
		return !m.re.MatchString(name)
	}
	return m.re.MatchString(name)
}

// compileGroupPatterns 编译一条 filter / exclude-filter（反引号可分隔多条子正则）。
//
// failOpen 决定"这条子正则 RE2 编译不出来"时往哪边降级：
//   - filter（failOpen=true）→ 该子正则视为**全部命中**，即不过滤，保留全部候选成员；
//   - exclude-filter（failOpen=false）→ 该子正则视为**全部不命中**，即不排除任何成员。
//
// 两个方向都往"多给几个节点"偏：宁可组里多几个本不该有的节点（用户看得见、能自己挑），
// 也不能让整个策略组凭空消失——组一旦没了，rules 里指向它的规则全成悬空引用，
// 客户端要么拒载整份配置，要么把流量悄悄丢给别的策略。
func compileGroupPatterns(groupName, field, patternText string, failOpen bool) []groupPatternMatcher {
	parts := strings.Split(patternText, "`")
	matchers := make([]groupPatternMatcher, 0, len(parts))
	for _, pattern := range parts {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if re, err := compileCompatibleRegex(pattern); err == nil {
			matchers = append(matchers, groupPatternMatcher{re: re})
			continue
		}
		// 编译失败先别急着降级：最常见的就是"锚在开头的负向先行断言"，
		// 它能保守地改写成"先全匹配、再按内层正则排除"，语义完全等价。
		if body, ok := rewriteNegativeLookaheadToExclusion(pattern); ok {
			if re, err := compileCompatibleRegex(body); err == nil {
				logger.Info("[模板V3] 正则含负向先行断言，已改写成等价的排除匹配",
					"group", groupName, "field", field, "pattern", pattern, "exclude", body)
				matchers = append(matchers, groupPatternMatcher{re: re, negate: true})
				continue
			}
		}
		logger.Warn("[模板V3] 正则 RE2 编译失败，已降级（filter=不过滤 / exclude-filter=不排除），宁可多给节点也不删组",
			"group", groupName, "field", field, "pattern", pattern)
		matchers = append(matchers, groupPatternMatcher{fixed: failOpen})
	}
	return matchers
}

// rewriteNegativeLookaheadToExclusion 把「整条正则 = 锚在开头的负向先行断言」保守改写成
// 一条"排除用"正则 body：原正则命中 ⇔ body 不命中。只认两种最常见的写法：
//
//	^((?!X).)*$  —— 任何位置都不以 X 开头，即"整串不含 X"
//	^(?!X)REST   —— REST 为空或 .* / .+ 时，即"开头不匹配 X"（X 以 .* 打头时同样是"不含 X"）
//
// 认不出来就返回 false，交给调用方走降级分支——不硬猜语义，猜错比降级更难排查。
func rewriteNegativeLookaheadToExclusion(pattern string) (string, bool) {
	p := stripRedundantOuterParens(strings.TrimSpace(pattern))

	// 形态一：^((?!X).)*$
	if strings.HasPrefix(p, "^((?!") {
		if end := matchingParen(p, 2); end > 0 && p[end+1:] == ".)*$" {
			return trimLeadingMatchAll(p[len("^((?!"):end]), true
		}
	}

	// 形态二：^(?!X)REST
	if strings.HasPrefix(p, "^(?!") {
		if end := matchingParen(p, 1); end > 0 {
			body := p[len("^(?!"):end]
			switch p[end+1:] {
			case "", "$", ".*", ".*$", ".+", ".+$":
				if strings.HasPrefix(body, ".*") {
					return trimLeadingMatchAll(body), true
				}
				// 没有 .* 前缀 = 只断言开头，补回 ^ 保持锚定
				return "^(?:" + body + ")", true
			}
		}
	}

	return "", false
}

// trimLeadingMatchAll 把 ".*X" 这种"任意前缀 + X"的断言体降成 X：
// RE2 的 MatchString 本来就是无锚搜索，留着 .* 只是白白拖慢匹配。
func trimLeadingMatchAll(body string) string {
	trimmed := strings.TrimPrefix(body, ".*")
	if trimmed == body {
		return body
	}
	trimmed = strings.TrimPrefix(trimmed, "?") // .*? 非贪婪写法
	if trimmed == "" {
		return body
	}
	return trimmed
}

// matchingParen 返回 s[open] 这个 '(' 对应的 ')' 下标，找不到返回 -1。
// 会跳过转义字符和字符组 [...] 里的括号。
func matchingParen(s string, open int) int {
	if open >= len(s) || s[open] != '(' {
		return -1
	}
	depth := 0
	inClass := false
	for i := open; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++ // 跳过被转义的下一个字节
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// stripRedundantOuterParens 脱掉整体包裹的普通括号（模板里常见 `(^(?!...).*)` 这种写法）。
// (?: / (?! 这类特殊组一律不动。
func stripRedundantOuterParens(p string) string {
	for len(p) > 2 && p[0] == '(' && p[1] != '?' {
		if matchingParen(p, 0) != len(p)-1 {
			return p
		}
		p = p[1 : len(p)-1]
	}
	return p
}

// applyFilterPreservingGroups applies filter but preserves proxy group names
func applyFilterPreservingGroups(groupName string, proxies []string, filterPattern string, proxyGroups []string) []string {
	matchers := compileGroupPatterns(groupName, "filter", filterPattern, true)
	if len(matchers) == 0 {
		// 没有任何可用的子正则（整条都是空白）→ 当作没写 filter，不能反过来把成员筛没
		return proxies
	}

	groupSet := make(map[string]bool)
	for _, g := range proxyGroups {
		groupSet[g] = true
	}

	var result []string
	for _, proxyName := range proxies {
		// Always keep proxy groups
		if groupSet[proxyName] {
			result = append(result, proxyName)
			continue
		}

		// Apply filter to non-group proxies
		for _, m := range matchers {
			if m.match(proxyName) {
				result = append(result, proxyName)
				break
			}
		}
	}
	return result
}

// updateProxiesInNode updates the proxies field in the YAML node
func (p *TemplateV3Processor) updateProxiesInNode(groupNode *yaml.Node, proxies []string) {
	// Find or create proxies field
	var proxiesIndex int = -1
	for i := 0; i < len(groupNode.Content); i += 2 {
		if groupNode.Content[i].Value == "proxies" {
			proxiesIndex = i + 1
			break
		}
	}

	// Create new proxies sequence node
	proxiesNode := &yaml.Node{
		Kind: yaml.SequenceNode,
		Tag:  "!!seq",
	}
	for _, proxyName := range proxies {
		node := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: proxyName,
		}
		// Check if string contains non-ASCII characters (like emoji)
		hasNonASCII := false
		for _, r := range proxyName {
			if r > 127 {
				hasNonASCII = true
				break
			}
		}
		if !hasNonASCII {
			node.Tag = "!!str"
		}
		proxiesNode.Content = append(proxiesNode.Content, node)
	}

	if proxiesIndex >= 0 {
		// Replace existing proxies
		groupNode.Content[proxiesIndex] = proxiesNode
	} else {
		// Add proxies field after name and type
		insertIndex := 4 // After name and type (2 key-value pairs = 4 nodes)
		if insertIndex > len(groupNode.Content) {
			insertIndex = len(groupNode.Content)
		}

		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: "proxies",
		}

		// Insert key and value
		newContent := make([]*yaml.Node, 0, len(groupNode.Content)+2)
		newContent = append(newContent, groupNode.Content[:insertIndex]...)
		newContent = append(newContent, keyNode, proxiesNode)
		newContent = append(newContent, groupNode.Content[insertIndex:]...)
		groupNode.Content = newContent
	}
}

// removeMihomoFields removes mihomo-specific fields from the proxy group
func (p *TemplateV3Processor) removeMihomoFields(groupNode *yaml.Node) {
	fieldsToRemove := map[string]bool{
		"use":                         true,
		"include-all":                 true,
		"include-type":                true,
		"include-all-proxies":         true,
		"include-all-providers":       true,
		"include-region-proxy-groups": true,
		"filter":                      true,
		"exclude-filter":              true,
		"exclude-type":                true,
	}

	newContent := make([]*yaml.Node, 0, len(groupNode.Content))
	for i := 0; i < len(groupNode.Content); i += 2 {
		key := groupNode.Content[i].Value
		if !fieldsToRemove[key] {
			newContent = append(newContent, groupNode.Content[i], groupNode.Content[i+1])
		}
	}
	groupNode.Content = newContent
}

// excludeByType excludes proxies by their type
func (p *TemplateV3Processor) excludeByType(proxies []string, excludeTypes []string) []string {
	proxyTypeMap := make(map[string]string)
	for _, proxy := range p.allProxies {
		proxyTypeMap[proxy.Name] = proxy.Type
	}

	var result []string
	for _, proxyName := range proxies {
		proxyType, ok := proxyTypeMap[proxyName]
		if !ok || !containsType(excludeTypes, proxyType) {
			result = append(result, proxyName)
		}
	}
	return result
}

// Helper functions

func extractProxyNodes(proxies []map[string]any) []ProxyNode {
	var nodes []ProxyNode
	for _, proxy := range proxies {
		name, _ := proxy["name"].(string)
		proxyType, _ := proxy["type"].(string)
		if name != "" && proxyType != "" {
			nodes = append(nodes, ProxyNode{Name: name, Type: strings.ToLower(proxyType)})
		}
	}
	return nodes
}

func parseTypeList(typeStr string) []string {
	parts := strings.Split(typeStr, "|")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(strings.ToLower(part))
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func containsType(types []string, proxyType string) bool {
	proxyType = strings.ToLower(proxyType)
	for _, t := range types {
		if t == proxyType {
			return true
		}
	}
	return false
}

func applyFilter(proxies []string, filterPattern string) []string {
	return applyFilterForGroup("", proxies, filterPattern)
}

func applyFilterForGroup(groupName string, proxies []string, filterPattern string) []string {
	matchers := compileGroupPatterns(groupName, "filter", filterPattern, true)
	if len(matchers) == 0 {
		return proxies
	}

	var result []string
	for _, proxyName := range proxies {
		for _, m := range matchers {
			if m.match(proxyName) {
				result = append(result, proxyName)
				break
			}
		}
	}
	return result
}

func applyExcludeFilter(proxies []string, excludePattern string) []string {
	return applyExcludeFilterForGroup("", proxies, excludePattern)
}

func applyExcludeFilterForGroup(groupName string, proxies []string, excludePattern string) []string {
	// 编译失败的子正则按"谁都排不掉"处理（failOpen=false），即宁可把节点留在组里
	matchers := compileGroupPatterns(groupName, "exclude-filter", excludePattern, false)

	var result []string
	for _, proxyName := range proxies {
		excluded := false
		for _, m := range matchers {
			if m.match(proxyName) {
				excluded = true
				break
			}
		}
		if !excluded {
			result = append(result, proxyName)
		}
	}
	return result
}

func removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}

// unescapeUnicode converts Unicode escape sequences back to original characters
// Handles both \uXXXX (BMP) and \UXXXXXXXX (supplementary planes like emoji)
func unescapeUnicode(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '\\' {
			if s[i+1] == 'U' && i+10 <= len(s) {
				// \UXXXXXXXX format (8 hex digits)
				hexStr := s[i+2 : i+10]
				if codePoint, ok := parseHexString(hexStr); ok {
					result.WriteRune(rune(codePoint))
					i += 10
					continue
				}
			} else if s[i+1] == 'u' && i+6 <= len(s) {
				// \uXXXX format (4 hex digits)
				hexStr := s[i+2 : i+6]
				if codePoint, ok := parseHexString(hexStr); ok {
					result.WriteRune(rune(codePoint))
					i += 6
					continue
				}
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}

// parseHexString parses a hex string to an integer
func parseHexString(s string) (int64, bool) {
	var result int64
	for _, c := range s {
		result *= 16
		if c >= '0' && c <= '9' {
			result += int64(c - '0')
		} else if c >= 'a' && c <= 'f' {
			result += int64(c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			result += int64(c - 'A' + 10)
		} else {
			return 0, false
		}
	}
	return result, true
}

// CollectUsedProxyNamesFromGroups 扫顶层 proxy-groups 收集真正被引用的"叶子节点名"(非组名、非内置词)。
// 跟 (*TemplateV3Processor).collectUsedProxyNames 算法等价,但不依赖 processor 实例:
//   - 第一遍把所有 group.name 收集到 groupNames(用于区分"组名引用"和"节点名引用")
//   - 第二遍扫每个 group.proxies 数组,排除组名 + DIRECT/REJECT/PASS,剩下的就是叶子节点
//
// 给订阅生成的后处理裁剪用(去掉顶层 proxies 里不被任何 group 引用的孤儿节点)。
func CollectUsedProxyNamesFromGroups(groupsNode *yaml.Node) map[string]bool {
	used := make(map[string]bool)
	if groupsNode == nil || groupsNode.Kind != yaml.SequenceNode {
		return used
	}

	// 第一遍:收集组名
	groupNames := make(map[string]bool)
	for _, g := range groupsNode.Content {
		if g.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(g.Content)-1; i += 2 {
			if g.Content[i].Value == "name" {
				groupNames[g.Content[i+1].Value] = true
				break
			}
		}
	}

	// 第二遍:扫 proxies 引用,过滤组名/内置词
	for _, g := range groupsNode.Content {
		if g.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(g.Content)-1; i += 2 {
			if g.Content[i].Value != "proxies" {
				continue
			}
			pn := g.Content[i+1]
			if pn.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range pn.Content {
				name := item.Value
				if name == "" || groupNames[name] || name == "DIRECT" || name == "REJECT" || name == "PASS" {
					continue
				}
				used[name] = true
			}
			break
		}
	}
	return used
}

// collectUsedProxyNames collects all proxy names used in processed proxy-groups
func (p *TemplateV3Processor) collectUsedProxyNames(groupsNode *yaml.Node) map[string]bool {
	usedNames := make(map[string]bool)
	proxyGroupNames := make(map[string]bool)

	// First, collect all proxy group names
	for _, name := range p.proxyGroups {
		proxyGroupNames[name] = true
	}
	for _, name := range p.regionGroupNames {
		proxyGroupNames[name] = true
	}

	// Collect proxy names from each group (excluding group names and built-in keywords)
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(groupNode.Content); i += 2 {
			if groupNode.Content[i].Value == "proxies" {
				proxiesNode := groupNode.Content[i+1]
				if proxiesNode.Kind == yaml.SequenceNode {
					for _, proxyNode := range proxiesNode.Content {
						name := proxyNode.Value
						// Exclude group names and built-in keywords
						if !proxyGroupNames[name] && name != "DIRECT" && name != "REJECT" && name != "PASS" {
							usedNames[name] = true
						}
					}
				}
				break
			}
		}
	}

	return usedNames
}

// collectProxiesByGroupName collects proxy names that belong to a specific group
func (p *TemplateV3Processor) collectProxiesByGroupName(groupsNode *yaml.Node, targetGroupName string) map[string]bool {
	result := make(map[string]bool)
	proxyGroupNames := make(map[string]bool)

	// First, collect all proxy group names
	for _, name := range p.proxyGroups {
		proxyGroupNames[name] = true
	}
	for _, name := range p.regionGroupNames {
		proxyGroupNames[name] = true
	}

	// Find the target group and collect its proxy names
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			continue
		}

		var groupName string
		var proxiesNode *yaml.Node

		for i := 0; i < len(groupNode.Content); i += 2 {
			key := groupNode.Content[i].Value
			if key == "name" {
				groupName = groupNode.Content[i+1].Value
			} else if key == "proxies" {
				proxiesNode = groupNode.Content[i+1]
			}
		}

		if groupName == targetGroupName && proxiesNode != nil && proxiesNode.Kind == yaml.SequenceNode {
			for _, proxyNode := range proxiesNode.Content {
				name := proxyNode.Value
				// Exclude group names and built-in keywords
				if !proxyGroupNames[name] && name != "DIRECT" && name != "REJECT" && name != "PASS" {
					result[name] = true
				}
			}
			break
		}
	}

	return result
}

// dialerProxyConfig maps a set of proxy names to their dialer-proxy group
type dialerProxyConfig struct {
	proxyNames  map[string]bool
	dialerProxy string
}

// collectDialerProxyGroupMap reads dialer-proxy-group field from proxy groups before processing
// Returns a map of group name -> dialer-proxy group name
func (p *TemplateV3Processor) collectDialerProxyGroupMap(groupsNode *yaml.Node) map[string]string {
	result := make(map[string]string)
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			continue
		}
		var name, dialerGroup string
		for i := 0; i < len(groupNode.Content); i += 2 {
			switch groupNode.Content[i].Value {
			case "name":
				name = groupNode.Content[i+1].Value
			case "dialer-proxy-group":
				dialerGroup = groupNode.Content[i+1].Value
			}
		}
		if name != "" && dialerGroup != "" {
			result[name] = dialerGroup
		}
	}
	return result
}

// buildDialerProxyConfigs builds dialer proxy configs using the group map and processed proxy-groups
func (p *TemplateV3Processor) buildDialerProxyConfigs(groupsNode *yaml.Node, groupMap map[string]string) []dialerProxyConfig {
	proxyGroupNames := make(map[string]bool)
	for _, name := range p.proxyGroups {
		proxyGroupNames[name] = true
	}
	for _, name := range p.regionGroupNames {
		proxyGroupNames[name] = true
	}

	// Build group name -> proxies node map for resolving group references
	groupProxiesMap := make(map[string]*yaml.Node)
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			continue
		}
		var name string
		var proxies *yaml.Node
		for i := 0; i < len(groupNode.Content); i += 2 {
			switch groupNode.Content[i].Value {
			case "name":
				name = groupNode.Content[i+1].Value
			case "proxies":
				proxies = groupNode.Content[i+1]
			}
		}
		if name != "" && proxies != nil && proxies.Kind == yaml.SequenceNode {
			groupProxiesMap[name] = proxies
		}
	}

	isBuiltIn := func(v string) bool {
		return v == "DIRECT" || v == "REJECT" || v == "PASS"
	}

	var configs []dialerProxyConfig
	for _, groupNode := range groupsNode.Content {
		if groupNode.Kind != yaml.MappingNode {
			continue
		}

		var groupName string
		var proxiesNode *yaml.Node
		for i := 0; i < len(groupNode.Content); i += 2 {
			switch groupNode.Content[i].Value {
			case "name":
				groupName = groupNode.Content[i+1].Value
			case "proxies":
				proxiesNode = groupNode.Content[i+1]
			}
		}

		dialerGroup, ok := groupMap[groupName]
		if !ok || !proxyGroupNames[dialerGroup] || proxiesNode == nil || proxiesNode.Kind != yaml.SequenceNode {
			continue
		}

		names := make(map[string]bool)
		for _, n := range proxiesNode.Content {
			v := n.Value
			if isBuiltIn(v) {
				continue
			}
			if !proxyGroupNames[v] {
				names[v] = true
			} else if refProxies, ok := groupProxiesMap[v]; ok {
				// Resolve group reference: add the referenced group's proxy nodes
				for _, rn := range refProxies.Content {
					rv := rn.Value
					if !proxyGroupNames[rv] && !isBuiltIn(rv) {
						names[rv] = true
					}
				}
			}
		}
		if len(names) > 0 {
			configs = append(configs, dialerProxyConfig{proxyNames: names, dialerProxy: dialerGroup})
		}
	}
	return configs
}

// updateTopLevelProxies adds or updates the top-level proxies list with used proxy configs
func (p *TemplateV3Processor) updateTopLevelProxies(rootMap *yaml.Node, proxies []map[string]any, usedProxyNames map[string]bool, dpConfigs []dialerProxyConfig) {
	if len(usedProxyNames) == 0 {
		return
	}

	// Build a map of proxy name to config
	proxyConfigMap := make(map[string]map[string]any)
	for _, proxy := range proxies {
		if name, ok := proxy["name"].(string); ok {
			proxyConfigMap[name] = proxy
		}
	}

	// Create ordered list of proxies (maintain order from p.allProxies)
	// Add dialer-proxy based on dialer-proxy-group configurations
	var orderedProxies []map[string]any
	for _, proxyNode := range p.allProxies {
		if usedProxyNames[proxyNode.Name] {
			if config, exists := proxyConfigMap[proxyNode.Name]; exists {
				for _, dpc := range dpConfigs {
					if dpc.proxyNames[proxyNode.Name] {
						config["dialer-proxy"] = dpc.dialerProxy
						break
					}
				}
				orderedProxies = append(orderedProxies, config)
			}
		}
	}

	if len(orderedProxies) == 0 {
		return
	}

	// Find existing proxies index or create new one
	var proxiesIndex int = -1
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "proxies" {
			proxiesIndex = i + 1
			break
		}
	}

	// Convert proxies to YAML nodes
	proxiesYAML, err := yaml.Marshal(orderedProxies)
	if err != nil {
		return
	}

	var proxiesNode yaml.Node
	if err := yaml.Unmarshal(proxiesYAML, &proxiesNode); err != nil {
		return
	}

	// proxiesNode is a DocumentNode containing the actual sequence
	if proxiesNode.Kind != yaml.DocumentNode || len(proxiesNode.Content) == 0 {
		return
	}
	actualProxiesNode := proxiesNode.Content[0]

	if proxiesIndex >= 0 {
		// Replace existing proxies
		rootMap.Content[proxiesIndex] = actualProxiesNode
	} else {
		// Insert proxies after dns (or at the beginning if dns not found)
		insertIndex := 0
		for i := 0; i < len(rootMap.Content); i += 2 {
			key := rootMap.Content[i].Value
			// Insert after common config keys
			if key == "dns" || key == "mode" || key == "log-level" || key == "allow-lan" || key == "port" || key == "socks-port" {
				insertIndex = i + 2
			}
		}

		// Create key node
		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: "proxies",
		}

		// Insert at the calculated position
		newContent := make([]*yaml.Node, 0, len(rootMap.Content)+2)
		newContent = append(newContent, rootMap.Content[:insertIndex]...)
		newContent = append(newContent, keyNode, actualProxiesNode)
		newContent = append(newContent, rootMap.Content[insertIndex:]...)
		rootMap.Content = newContent
	}
}
