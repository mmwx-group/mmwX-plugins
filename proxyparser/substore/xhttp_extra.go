package substore

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// XHTTP 进阶选项:mihomo 的 xhttp-opts 写法 → Xray 分享链接的 extra(JSON,即 xhttpSettings 去掉 host / path / mode)。
//
// Xray 的语义要点(infra/conf/transport_method.go 的 SplitHTTPConfig):
//   - 链接里带了 extra,Xray 就拿 extra 当整份 xhttpSettings,外面只取 host / path / mode。
//   - headers 里不能有 Host(Host 走 host 参数)。
//   - 范围值(xPaddingBytes、scMaxEachPostBytes、xmux 各项)写数字或 "a-b" 字符串都认;hKeepAlivePeriod 只认数字。
//   - downloadSettings 是一整份 streamSettings,不会沿用主连接:没写的字段这里按 mihomo 的沿用规则补全
//     (地址 / 端口 / TLS / REALITY / SNI / ALPN / 指纹 / path / host / headers / 填充 / 复用都跟主连接)。

// xhttpRangeFields mihomo 写法 → Xray 写法(值是数字或 "a-b")。
var xhttpRangeFields = []struct{ mihomo, xray string }{
	{"x-padding-bytes", "xPaddingBytes"},
	{"session-length", "sessionIDLength"},
	{"uplink-chunk-size", "uplinkChunkSize"},
	{"sc-max-each-post-bytes", "scMaxEachPostBytes"},
	{"sc-min-posts-interval-ms", "scMinPostsIntervalMs"},
}

// xhttpStringFields mihomo 写法 → Xray 写法(字符串)。
var xhttpStringFields = []struct{ mihomo, xray string }{
	{"x-padding-key", "xPaddingKey"},
	{"x-padding-header", "xPaddingHeader"},
	{"x-padding-placement", "xPaddingPlacement"},
	{"x-padding-method", "xPaddingMethod"},
	{"uplink-http-method", "uplinkHTTPMethod"},
	{"session-placement", "sessionIDPlacement"},
	{"session-key", "sessionIDKey"},
	{"session-table", "sessionIDTable"},
	{"seq-placement", "seqPlacement"},
	{"seq-key", "seqKey"},
	{"uplink-data-placement", "uplinkDataPlacement"},
	{"uplink-data-key", "uplinkDataKey"},
}

// xhttpBoolFields mihomo 写法 → Xray 写法(只写 true)。
var xhttpBoolFields = []struct{ mihomo, xray string }{
	{"no-grpc-header", "noGRPCHeader"},
	{"x-padding-obfs-mode", "xPaddingObfsMode"},
}

// xhttpReuseFields mihomo reuse-settings → Xray xmux(范围值)。
var xhttpReuseFields = []struct{ mihomo, xray string }{
	{"max-concurrency", "maxConcurrency"},
	{"max-connections", "maxConnections"},
	{"c-max-reuse-times", "cMaxReuseTimes"},
	{"h-max-request-times", "hMaxRequestTimes"},
	{"h-max-reusable-secs", "hMaxReusableSecs"},
}

// xhttpAnyMap 把 map[string]interface{} / map[string]string / map[interface{}]interface{} 统一成 map[string]interface{}。
func xhttpAnyMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case map[string]string:
		out := make(map[string]interface{}, len(m))
		for k, s := range m {
			out[k] = s
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, s := range m {
			out[fmt.Sprint(k)] = s
		}
		return out
	}
	return nil
}

// xhttpRangeValue 范围值原样带过去:整数写数字,"a-b" / "123" 写字符串;空值返回 nil。
func xhttpRangeValue(v interface{}) interface{} {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return t
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
	case string:
		if s := strings.Join(strings.Fields(t), ""); s != "" {
			return s
		}
	}
	return nil
}

// xhttpIntValue 整数值(数字或数字字符串);读不出返回 false。
func xhttpIntValue(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// xhttpHeadersWithoutHost headers 去掉 Host(不分大小写);一个都不剩返回 nil。
func xhttpHeadersWithoutHost(v interface{}) map[string]interface{} {
	headers := xhttpAnyMap(v)
	out := map[string]interface{}{}
	for k, val := range headers {
		if strings.EqualFold(k, "host") {
			continue
		}
		if s := fmt.Sprint(val); val != nil {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// xhttpHost 取 Host:xhttp-opts.host 优先,其次 headers 里的 Host。
func xhttpHost(opts map[string]interface{}) string {
	if h := GetString(opts, "host"); h != "" {
		return h
	}
	for k, v := range xhttpAnyMap(opts["headers"]) {
		if strings.EqualFold(k, "host") {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// xhttpMode 取模式:xhttp-opts.mode 优先(mihomo 只读它),其次节点顶层的 mode。
func xhttpMode(proxy Proxy, opts map[string]interface{}) string {
	if m := GetString(opts, "mode"); m != "" {
		return m
	}
	return GetString(proxy, "mode")
}

// xhttpXmux reuse-settings → xmux;什么都没有返回 nil。
func xhttpXmux(v interface{}) map[string]interface{} {
	reuse := xhttpAnyMap(v)
	if reuse == nil {
		return nil
	}
	xmux := map[string]interface{}{}
	for _, f := range xhttpReuseFields {
		if val := xhttpRangeValue(reuse[f.mihomo]); val != nil {
			xmux[f.xray] = val
		}
	}
	if n, ok := xhttpIntValue(reuse["h-keep-alive-period"]); ok && n != 0 {
		xmux["hKeepAlivePeriod"] = n
	}
	if len(xmux) == 0 {
		return nil
	}
	return xmux
}

// xhttpExtraFields 把 xhttp-opts 里的进阶选项写成 Xray 写法(不含 host / path / mode / downloadSettings)。
func xhttpExtraFields(opts map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	if headers := xhttpHeadersWithoutHost(opts["headers"]); headers != nil {
		out["headers"] = headers
	}
	for _, f := range xhttpBoolFields {
		if GetBool(opts, f.mihomo) {
			out[f.xray] = true
		}
	}
	for _, f := range xhttpStringFields {
		if s := GetString(opts, f.mihomo); s != "" {
			out[f.xray] = s
		}
	}
	for _, f := range xhttpRangeFields {
		if val := xhttpRangeValue(opts[f.mihomo]); val != nil {
			out[f.xray] = val
		}
	}
	if xmux := xhttpXmux(opts["reuse-settings"]); xmux != nil {
		out["xmux"] = xmux
	}
	return out
}

// xhttpPick download-settings 里写了就用它,没写沿用主连接。
func xhttpPick(ds map[string]interface{}, key string, main interface{}) interface{} {
	if v, ok := ds[key]; ok && v != nil {
		return v
	}
	return main
}

// xhttpDownloadSettings download-settings → Xray 的 downloadSettings(完整的 streamSettings,没写的按主连接补全)。
func xhttpDownloadSettings(proxy Proxy, opts map[string]interface{}) map[string]interface{} {
	ds := xhttpAnyMap(opts["download-settings"])
	if ds == nil {
		return nil
	}
	out := map[string]interface{}{"network": "xhttp"}

	if addr := fmt.Sprint(xhttpPick(ds, "server", GetString(proxy, "server"))); addr != "" {
		out["address"] = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	}
	if port, ok := xhttpIntValue(xhttpPick(ds, "port", proxy["port"])); ok && port > 0 {
		out["port"] = port
	}

	mainReality := GetMap(proxy, "reality-opts")
	reality := xhttpAnyMap(xhttpPick(ds, "reality-opts", mainReality))
	tls := GetBool(proxy, "tls") || mainReality != nil
	if v, ok := ds["tls"]; ok && v != nil {
		tls = GetBool(ds, "tls")
	}
	serverName, _ := xhttpPick(ds, "servername", GetSNI(proxy)).(string)
	clientFP, _ := xhttpPick(ds, "client-fingerprint", GetString(proxy, "client-fingerprint")).(string)

	switch {
	case !tls:
		out["security"] = "none"
	case reality != nil:
		out["security"] = "reality"
		rs := map[string]interface{}{}
		if serverName != "" {
			rs["serverName"] = serverName
		}
		if clientFP == "" {
			clientFP = "chrome" // REALITY 必须带指纹;mihomo 系缺省也是 chrome
		}
		rs["fingerprint"] = clientFP
		if pbk := GetString(reality, "public-key"); pbk != "" {
			rs["publicKey"] = pbk
		}
		if sid := GetAnyString(reality, "short-id"); sid != "" {
			rs["shortId"] = sid
		}
		if spx := GetString(reality, "spider-x"); spx != "" {
			rs["spiderX"] = spx
		}
		out["realitySettings"] = rs
	default:
		out["security"] = "tls"
		ts := map[string]interface{}{}
		if serverName != "" {
			ts["serverName"] = serverName
		}
		var alpn []string
		if _, ok := ds["alpn"]; ok {
			alpn = GetStringSlice(ds, "alpn")
		} else {
			alpn = GetStringSlice(proxy, "alpn")
		}
		if len(alpn) > 0 {
			ts["alpn"] = alpn
		}
		if clientFP != "" {
			ts["fingerprint"] = clientFP
		}
		// 证书指纹:mihomo 的 download-settings 叫 fingerprint,主连接是 tls-fingerprint(妙妙屋X)或 fingerprint。
		// 新版 Xray 删了 allowInsecure(写了直接报错),有指纹就只写 pinnedPeerCertSha256。
		mainPin := GetString(proxy, "tls-fingerprint")
		if mainPin == "" {
			mainPin = GetString(proxy, "fingerprint")
		}
		pin, _ := xhttpPick(ds, "fingerprint", mainPin).(string)
		if pin != "" {
			ts["pinnedPeerCertSha256"] = pin
		} else if skip, _ := xhttpPick(ds, "skip-cert-verify", proxy["skip-cert-verify"]).(bool); skip {
			ts["allowInsecure"] = true
		}
		if len(ts) > 0 {
			out["tlsSettings"] = ts
		}
	}

	// xhttpSettings:先拿主连接的整份 xhttp-opts(填充、会话 ID 等两端要一致的选项下行也得带上),
	// 再用 download-settings 里写了的 path / host / headers / reuse-settings 覆盖。
	merged := map[string]interface{}{}
	for k, v := range opts {
		if k != "download-settings" {
			merged[k] = v
		}
	}
	if v, ok := ds["headers"]; ok {
		merged["headers"] = v
	}
	if v, ok := ds["reuse-settings"]; ok {
		merged["reuse-settings"] = v
	}
	xs := xhttpExtraFields(merged)
	if path := fmt.Sprint(xhttpPick(ds, "path", GetString(opts, "path"))); path != "" {
		xs["path"] = path
	}
	host, _ := ds["host"].(string)
	if host == "" {
		host = xhttpHost(opts)
	}
	if host != "" {
		xs["host"] = host
	}
	if mode := xhttpMode(proxy, opts); mode != "" {
		xs["mode"] = mode
	}
	out["xhttpSettings"] = xs
	return out
}

// buildXHTTPExtra 节点的 XHTTP 进阶选项写成分享链接的 extra(紧凑 JSON);没有进阶选项返回 ""。
func buildXHTTPExtra(proxy Proxy, opts map[string]interface{}) string {
	if opts == nil {
		return ""
	}
	extra := xhttpExtraFields(opts)
	if dl := xhttpDownloadSettings(proxy, opts); dl != nil {
		extra["downloadSettings"] = dl
	}
	if len(extra) == 0 {
		return ""
	}
	b, err := json.Marshal(extra)
	if err != nil {
		return ""
	}
	return string(b)
}
