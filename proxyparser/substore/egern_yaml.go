package substore

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// emitEgernYAML 把 producer 组好的结构写成**块状 YAML**。
//
// 为什么不直接 yaml.Marshal:yaml.v3 的 is_printable 只覆盖到 3 字节 UTF-8,4 字节的
// emoji 一律判为不可打印 → 强制双引号 + \U 转义,节点名「🇺🇸 美国06」会变成
// "\U0001F1FA\U0001F1F8 美国06"。放开这层转义的 yaml_emitter_set_unicode 是内部 API,
// Encoder 够不着(template_merger.go 也是为此绕开 yaml.Marshal 的)。节点名几乎都带
// 国旗,所以这里自己写一个只覆盖本 producer 输出形状的块状发射器。
//
// 之前发的是 JSON-in-YAML(`- {"vless":{...}}`)。那在规范上是合法 YAML —— JSON 是
// YAML 的子集 —— 但 Egern 的解析器不收,官方文档给的也是块状。块状写法所有 YAML
// 解析器都认,是严格更安全的一侧。
func emitEgernYAML(items []map[string]interface{}) string {
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for _, item := range items {
		writeEgernSeqMapping(&sb, item, "  ")
	}
	return sb.String()
}

// writeEgernSeqMapping 写一个「序列项就是一个映射」的条目:首键跟在 "- " 后面,
// 其余键与首键对齐。
func writeEgernSeqMapping(sb *strings.Builder, m map[string]interface{}, indent string) {
	keys := sortedEgernKeys(m)
	if len(keys) == 0 {
		sb.WriteString(indent + "- {}\n")
		return
	}
	for i, k := range keys {
		prefix := indent + "  "
		if i == 0 {
			prefix = indent + "- "
		}
		writeEgernEntry(sb, k, m[k], prefix, indent+"  ")
	}
}

// writeEgernEntry 写一对 key/value。prefix 是这一行实际要用的前缀(序列首项是 "- "),
// childIndent 是嵌套内容的基准缩进。
func writeEgernEntry(sb *strings.Builder, key string, value interface{}, prefix, childIndent string) {
	name := egernKey(key)
	if m, ok := asEgernMapping(value); ok {
		if len(m) == 0 {
			sb.WriteString(prefix + name + ": {}\n")
			return
		}
		sb.WriteString(prefix + name + ":\n")
		writeEgernMapping(sb, m, childIndent+"  ")
		return
	}
	if seq, ok := asEgernSequence(value); ok {
		if len(seq) == 0 {
			sb.WriteString(prefix + name + ": []\n")
			return
		}
		sb.WriteString(prefix + name + ":\n")
		writeEgernSequence(sb, seq, childIndent+"  ")
		return
	}
	sb.WriteString(prefix + name + ": " + egernScalar(value) + "\n")
}

func writeEgernMapping(sb *strings.Builder, m map[string]interface{}, indent string) {
	for _, k := range sortedEgernKeys(m) {
		writeEgernEntry(sb, k, m[k], indent, indent)
	}
}

func writeEgernSequence(sb *strings.Builder, items []interface{}, indent string) {
	for _, item := range items {
		if m, ok := asEgernMapping(item); ok {
			writeEgernSeqMapping(sb, m, indent)
			continue
		}
		if seq, ok := asEgernSequence(item); ok {
			sb.WriteString(indent + "-\n")
			writeEgernSequence(sb, seq, indent+"  ")
			continue
		}
		sb.WriteString(indent + "- " + egernScalar(item) + "\n")
	}
}

// asEgernMapping / asEgernSequence 用反射认复合值,不靠类型断言。
//
// producer 里流过的映射不止 map[string]interface{}:还有具名的 Proxy(底层同样是
// map[string]interface{}),而 Go 的类型 switch **不会**把具名类型匹配到它的底层类型。
// 之前写成 `case map[string]interface{}` 时,Proxy 全部掉进 default,被 fmt 打成
// "map[dns_servers:[...] ...]" 直接塞进 YAML —— 产物是坏的,而按子串断言的老测试
// 照样全绿。
func asEgernMapping(v interface{}) (map[string]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Map {
		return nil, false
	}
	out := make(map[string]interface{}, rv.Len())
	for _, k := range rv.MapKeys() {
		out[fmt.Sprint(k.Interface())] = rv.MapIndex(k).Interface()
	}
	return out, true
}

func asEgernSequence(v interface{}) ([]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	rv := reflect.ValueOf(v)
	// []byte 是字节串不是序列,按标量处理。
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	if rv.Type().Elem().Kind() == reflect.Uint8 {
		return nil, false
	}
	out := make([]interface{}, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

func sortedEgernKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func egernKey(k string) string {
	if isPlainEgernScalar(k) {
		return k
	}
	return quoteEgernString(k)
}

func egernScalar(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		if isPlainEgernScalar(x) {
			return x
		}
		return quoteEgernString(x)
	case float64:
		// JSON 数字都是 float64;整数值要写成整数,不能出现 443.0 这种端口。
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case float32:
		return egernScalar(float64(x))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", x)
	default:
		return egernScalar(fmt.Sprintf("%v", x))
	}
}

// quoteEgernString 用单引号包起来。单引号风格里只有单引号本身需要转义(写两遍),
// **其余字节原样保留** —— emoji 因此能照原样出现,这正是不用 yaml.Marshal 的原因。
func quoteEgernString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// egernNumberLike 匹配「会被 YAML 当成数字」的字符串,这类必须加引号,
// 否则 "080" / "1e5" 这种值读回来就不是字符串了。
var egernNumberLike = regexp.MustCompile(`^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$`)

// egernReservedWords 是 YAML 里会被读成布尔/空值的裸词(YAML 1.1 口径,各解析器实现不一,
// 一律加引号最省事)。
var egernReservedWords = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true, "on": true, "off": true,
	"null": true, "~": true, "y": true, "n": true,
}

// isPlainEgernScalar 判断一个字符串能不能不加引号直接写。判不准时一律返回 false
// (加引号永远是安全的一侧),所以这里可以从严。
func isPlainEgernScalar(s string) bool {
	if s == "" {
		return false
	}
	if strings.TrimSpace(s) != s {
		return false
	}
	if egernReservedWords[strings.ToLower(s)] || egernNumberLike.MatchString(s) {
		return false
	}
	// 控制字符与换行:一律加引号(单引号风格也放不下换行,但这些值本就不该出现)。
	if strings.ContainsAny(s, "\n\r\t") {
		return false
	}
	// 行内歧义:": " 会被读成键值分隔,"​ #" 会被读成注释起点。
	if strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasSuffix(s, ":") {
		return false
	}
	// 首字符是 YAML 指示符的,一律加引号。
	switch s[0] {
	case '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`':
		return false
	}
	return true
}
