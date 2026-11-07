package proxyparser

import (
	"encoding/json"
	"strconv"
	"strings"
)

// vless:// 链接里 XHTTP 的 extra(Xray 写法的 JSON,即 xhttpSettings 去掉 host / path / mode)→ mihomo 的 xhttp-opts。
// 字段对照与 substore/xhttp_extra.go 的导出方向相同;范围值统一写成字符串("123" / "a-b"),
// h-keep-alive-period 是整数(mihomo 的类型)。

var xhttpExtraRangeFields = map[string]string{
	"xPaddingBytes":        "x-padding-bytes",
	"sessionIDLength":      "session-length",
	"uplinkChunkSize":      "uplink-chunk-size",
	"scMaxEachPostBytes":   "sc-max-each-post-bytes",
	"scMinPostsIntervalMs": "sc-min-posts-interval-ms",
}

var xhttpExtraStringFields = map[string]string{
	"xPaddingKey":         "x-padding-key",
	"xPaddingHeader":      "x-padding-header",
	"xPaddingPlacement":   "x-padding-placement",
	"xPaddingMethod":      "x-padding-method",
	"uplinkHTTPMethod":    "uplink-http-method",
	"sessionIDPlacement":  "session-placement",
	"sessionIDKey":        "session-key",
	"sessionIDTable":      "session-table",
	"seqPlacement":        "seq-placement",
	"seqKey":              "seq-key",
	"uplinkDataPlacement": "uplink-data-placement",
	"uplinkDataKey":       "uplink-data-key",
}

var xhttpExtraBoolFields = map[string]string{
	"noGRPCHeader":     "no-grpc-header",
	"xPaddingObfsMode": "x-padding-obfs-mode",
}

var xhttpExtraXmuxFields = map[string]string{
	"maxConcurrency":   "max-concurrency",
	"maxConnections":   "max-connections",
	"cMaxReuseTimes":   "c-max-reuse-times",
	"hMaxRequestTimes": "h-max-request-times",
	"hMaxReusableSecs": "h-max-reusable-secs",
}

// xhttpExtraRange Xray 的范围值(数字或 "a-b" 字符串)→ 字符串;空 / 0 / 读不出返回 ""。
func xhttpExtraRange(v any) string {
	switch t := v.(type) {
	case float64:
		if t != 0 && t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
	case string:
		return strings.Join(strings.Fields(t), "")
	}
	return ""
}

// xhttpExtraReuse xmux → reuse-settings;什么都没有返回 nil。
func xhttpExtraReuse(v any) map[string]any {
	xmux, _ := v.(map[string]any)
	reuse := map[string]any{}
	for xray, mihomo := range xhttpExtraXmuxFields {
		if s := xhttpExtraRange(xmux[xray]); s != "" {
			reuse[mihomo] = s
		}
	}
	switch t := xmux["hKeepAlivePeriod"].(type) {
	case float64:
		if t != 0 {
			reuse["h-keep-alive-period"] = int(t)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil && n != 0 {
			reuse["h-keep-alive-period"] = n
		}
	}
	if len(reuse) == 0 {
		return nil
	}
	return reuse
}

// xhttpExtraHeaders headers 对象 → map[string]string(去掉 Host:Xray 不许写在这里)。
func xhttpExtraHeaders(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for k, val := range m {
		if s, ok := val.(string); ok && !strings.EqualFold(k, "host") {
			out[k] = s
		}
	}
	return out
}

// applyXHTTPSettings 把一份 Xray 写法的 xhttpSettings(进阶部分)写进 mihomo 的 opts。
func applyXHTTPSettings(opts map[string]any, xs map[string]any) {
	if headers := xhttpExtraHeaders(xs["headers"]); len(headers) > 0 {
		merged, _ := opts["headers"].(map[string]string)
		if merged == nil {
			merged = map[string]string{}
		}
		for k, v := range headers {
			merged[k] = v
		}
		opts["headers"] = merged
	}
	for xray, mihomo := range xhttpExtraBoolFields {
		if b, _ := xs[xray].(bool); b {
			opts[mihomo] = true
		}
	}
	for xray, mihomo := range xhttpExtraStringFields {
		if s, _ := xs[xray].(string); s != "" {
			opts[mihomo] = s
		}
	}
	for xray, mihomo := range xhttpExtraRangeFields {
		if s := xhttpExtraRange(xs[xray]); s != "" {
			opts[mihomo] = s
		}
	}
	if reuse := xhttpExtraReuse(xs["xmux"]); reuse != nil {
		opts["reuse-settings"] = reuse
	}
}

// xhttpExtraDownload Xray 的 downloadSettings(一整份 streamSettings)→ mihomo 的 download-settings。
// Xray 不沿用主连接,所以 TLS 开没开照 security 明写(没写 security = 不加密)。
func xhttpExtraDownload(dl map[string]any) map[string]any {
	ds := map[string]any{}
	if addr, _ := dl["address"].(string); addr != "" {
		ds["server"] = addr
	}
	if port, ok := dl["port"].(float64); ok && port > 0 {
		ds["port"] = int(port)
	} else if s, ok := dl["port"].(string); ok {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			ds["port"] = n
		}
	}
	security, _ := dl["security"].(string)
	security = strings.ToLower(strings.TrimSpace(security))
	ds["tls"] = security == "tls" || security == "reality"

	if ts, ok := dl["tlsSettings"].(map[string]any); ok && security == "tls" {
		if sn, _ := ts["serverName"].(string); sn != "" {
			ds["servername"] = sn
		}
		if fp, _ := ts["fingerprint"].(string); fp != "" {
			ds["client-fingerprint"] = fp
		}
		switch alpn := ts["alpn"].(type) {
		case []any:
			list := []string{}
			for _, a := range alpn {
				if s, ok := a.(string); ok && s != "" {
					list = append(list, s)
				}
			}
			if len(list) > 0 {
				ds["alpn"] = list
			}
		case string:
			if alpn != "" {
				ds["alpn"] = strings.Split(alpn, ",")
			}
		}
		if pin, _ := ts["pinnedPeerCertSha256"].(string); pin != "" {
			ds["fingerprint"] = pin // mihomo 的证书指纹字段
		}
		if b, _ := ts["allowInsecure"].(bool); b {
			ds["skip-cert-verify"] = true
		}
	}
	if rs, ok := dl["realitySettings"].(map[string]any); ok && security == "reality" {
		if sn, _ := rs["serverName"].(string); sn != "" {
			ds["servername"] = sn
		}
		if fp, _ := rs["fingerprint"].(string); fp != "" {
			ds["client-fingerprint"] = fp
		}
		reality := map[string]any{}
		if pbk, _ := rs["publicKey"].(string); pbk != "" {
			reality["public-key"] = pbk
		}
		if sid, _ := rs["shortId"].(string); sid != "" {
			reality["short-id"] = sid
		}
		if spx, _ := rs["spiderX"].(string); spx != "" {
			reality["spider-x"] = spx
		}
		ds["reality-opts"] = reality
	}

	xs, _ := dl["xhttpSettings"].(map[string]any)
	if xs == nil {
		xs, _ = dl["splithttpSettings"].(map[string]any)
	}
	if xs != nil {
		if path, _ := xs["path"].(string); path != "" {
			ds["path"] = path
		}
		if host, _ := xs["host"].(string); host != "" {
			ds["host"] = host
		}
		if headers := xhttpExtraHeaders(xs["headers"]); len(headers) > 0 {
			ds["headers"] = headers
		}
		// xmux 可能直接写在 xhttpSettings 里,也可能在它的 extra 里(mihomo / Sub-Store 的写法)
		xmux := xs["xmux"]
		if inner, ok := xs["extra"].(map[string]any); ok && inner["xmux"] != nil {
			xmux = inner["xmux"]
		}
		if reuse := xhttpExtraReuse(xmux); reuse != nil {
			ds["reuse-settings"] = reuse
		}
	}
	return ds
}

// applyXHTTPExtra 解析 vless:// 的 extra 写进 xhttp-opts;不是 JSON 对象就忽略。
func applyXHTTPExtra(opts map[string]any, extra string) {
	if strings.TrimSpace(extra) == "" {
		return
	}
	var xs map[string]any
	if err := json.Unmarshal([]byte(extra), &xs); err != nil || xs == nil {
		return
	}
	applyXHTTPSettings(opts, xs)
	if dl, ok := xs["downloadSettings"].(map[string]any); ok {
		if ds := xhttpExtraDownload(dl); len(ds) > 0 {
			opts["download-settings"] = ds
		}
	}
}
