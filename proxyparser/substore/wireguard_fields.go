package substore

import (
	"fmt"
	"strings"
)

// normalizeWireGuardOptionalFields 统一 clash 系 producer(clash / clashmeta / stash /
// shadowrocket)对 WG 可选字段的处理。
//
// keepalive 与 persistent-keepalive、preshared-key 与 pre-shared-key 是同一个值的两种写法,
// 上游 JS 两个都写,但取不到值时是 undefined,序列化时自然消失。Go 移植版以前无条件写成
// 0 / "":sing-box 先过一遍 ClashMeta internal,再把认不出的键透传出去,于是每个 WG endpoint
// 都多一个 persistent_keepalive: 0,官方 sing-box 遇到未知字段整份拒载;stash / shadowrocket
// 也会多出零值 keepalive 与空 psk。
//
// 这里只在值非零 / 非空时写两个别名,否则两个都删掉(0 本来就表示不发保活)。
func normalizeWireGuardOptionalFields(proxy Proxy) {
	keepalive := GetInt(proxy, "keepalive")
	if keepalive <= 0 {
		keepalive = GetInt(proxy, "persistent-keepalive")
	}
	if keepalive > 0 {
		proxy["keepalive"] = keepalive
		proxy["persistent-keepalive"] = keepalive
	} else {
		delete(proxy, "keepalive")
		delete(proxy, "persistent-keepalive")
	}

	psk := GetString(proxy, "preshared-key")
	if psk == "" {
		psk = GetString(proxy, "pre-shared-key")
	}
	if psk != "" {
		proxy["preshared-key"] = psk
		proxy["pre-shared-key"] = psk
	} else {
		delete(proxy, "preshared-key")
		delete(proxy, "pre-shared-key")
	}
}

// wireGuardKeepalive 取 WG 顶层保活间隔(persistent-keepalive 优先,其次 keepalive),
// 取不到或不是正数时返回 0。
func wireGuardKeepalive(proxy Proxy) int {
	if v := GetInt(proxy, "persistent-keepalive"); v > 0 {
		return v
	}
	if v := GetInt(proxy, "keepalive"); v > 0 {
		return v
	}
	return 0
}

// wireGuardStringList 把 allowed-ips 这类「列表或逗号分隔字符串」统一成 []string。
// 数据可能来自 YAML([]interface{})、URI 解析([]string)或手写的逗号串,三种都要认;
// 以前 Loon 只认 []interface{} 和 string,[]string 会被当成没写而静默回落默认值。
func wireGuardStringList(v interface{}) []string {
	var raw []string
	switch list := v.(type) {
	case []string:
		raw = list
	case []interface{}:
		for _, item := range list {
			if item != nil {
				raw = append(raw, fmt.Sprintf("%v", item))
			}
		}
	case string:
		raw = strings.Split(list, ",")
	default:
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
