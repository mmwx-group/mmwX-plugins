package substore

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Loon 的 Snell(v4 / v5)与 VLESS / VMess(AEAD)/ Trojan 的 XHTTP 传输,跟上游 Sub-Store 92ea17c8(2026-11-19)。
// 从前 Loon producer 没有 snell 分支,Snell 节点一律被当成不支持的协议跳过,Loon 订阅里没有它们。

// loonXhttpFields Loon 的 xhttp-<键> → clash xhttp-opts 里的字段(上游 LOON_XHTTP_FIELDS,顺序照抄)。
var loonXhttpFields = [][2]string{
	{"mode", "mode"},
	{"uplink-method", "uplink-http-method"},
	{"min-post-interval-ms", "sc-min-posts-interval-ms"},
	{"max-post-bytes", "sc-max-each-post-bytes"},
	{"uplink-data-placement", "uplink-data-placement"},
	{"uplink-data-key", "uplink-data-key"},
	{"uplink-chunk-size", "uplink-chunk-size"},
	{"padding-bytes", "x-padding-bytes"},
	{"padding-obfs-mode", "x-padding-obfs-mode"},
	{"padding-placement", "x-padding-placement"},
	{"padding-key", "x-padding-key"},
	{"padding-header", "x-padding-header"},
	{"padding-method", "x-padding-method"},
	{"no-grpc-header", "no-grpc-header"},
	{"session-id-placement", "session-placement"},
	{"session-id-key", "session-key"},
	{"session-id-table", "session-table"},
	{"session-id-length", "session-length"},
	{"seq-placement", "seq-placement"},
	{"seq-key", "seq-key"},
}

// loonValueText 选项值的文本:数字不出现科学计数法,布尔照写。
func loonValueText(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	default:
		return fmt.Sprint(x)
	}
}

// loonFormatValue Loon 选项值:带逗号 / 空白 / 空串(或要求加引号)时套双引号;
// 含双引号或换行的没法写进 Loon 的一行配置,报错跳过这个节点(上游 formatLoonValue)。
func loonFormatValue(v interface{}, quoted bool) (string, error) {
	text := loonValueText(v)
	if strings.ContainsAny(text, "\"\r\n") {
		return "", fmt.Errorf("unsupported characters in Loon option")
	}
	if quoted || text == "" || strings.ContainsAny(text, ", \t") {
		return `"` + text + `"`, nil
	}
	return text, nil
}

// snell Loon 只支持 Snell v4 / v5,混淆只有 http。
func (p *LoonProducer) snell(proxy Proxy) (string, error) {
	version := GetInt(proxy, "version")
	if version != 4 && version != 5 {
		v := "1"
		if IsPresent(proxy, "version") {
			v = loonValueText(proxy["version"])
		}
		return "", fmt.Errorf("Loon does not support Snell version %s", v)
	}
	psk := GetString(proxy, "psk")
	if psk == "" {
		return "", fmt.Errorf("missing Snell PSK")
	}
	obfs := GetMap(proxy, "obfs-opts")
	obfsMode := ""
	if obfs != nil {
		obfsMode = GetString(obfs, "mode")
	}
	if GetString(proxy, "plugin") != "" || (obfsMode != "" && obfsMode != "none" && obfsMode != "http") {
		return "", fmt.Errorf("Loon Snell only supports HTTP obfs")
	}
	quotedPSK, err := loonFormatValue(psk, true)
	if err != nil {
		return "", err
	}

	result := NewResult(proxy)
	result.Append(fmt.Sprintf("%s=snell,%s,%d,%s,version=%d",
		GetString(proxy, "name"),
		GetString(proxy, "server"),
		GetInt(proxy, "port"),
		quotedPSK,
		version))
	if obfsMode == "http" {
		result.Append(",obfs=http")
		for _, kv := range [][2]string{{"obfs-host", "host"}, {"obfs-uri", "path"}} {
			if v, ok := obfs[kv[1]]; ok && v != nil {
				text, err := loonFormatValue(v, false)
				if err != nil {
					return "", err
				}
				result.Append(fmt.Sprintf(",%s=%s", kv[0], text))
			}
		}
	}
	if IsPresent(proxy, "udp") {
		result.Append(fmt.Sprintf(",udp=%v", GetBool(proxy, "udp")))
	}
	p.appendBlockQuic(result, proxy)
	p.appendIPVersion(result, proxy)
	return result.String(), nil
}

// appendLoonXhttp transport=xhttp + path / host + xhttp-* 选项 + 其余请求头(上游 appendXhttp)。
// Loon 的 XHTTP 没有下行分离(download-settings),带了就报错跳过。
func appendLoonXhttp(result *Result, proxy Proxy) error {
	xhttp := GetMap(proxy, "xhttp-opts")
	if xhttp != nil && xhttp["download-settings"] != nil {
		return fmt.Errorf("Loon XHTTP does not support download-settings")
	}
	headers := map[string]interface{}{}
	if xhttp != nil {
		if h := GetMap(xhttp, "headers"); h != nil {
			headers = h
		}
	}
	// 请求头按名字排序,输出稳定(JS 是对象插入顺序,Go map 无序)
	headerKeys := make([]string, 0, len(headers))
	for k := range headers {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	var host interface{}
	if xhttp != nil && xhttp["host"] != nil {
		host = xhttp["host"]
	} else {
		for _, k := range headerKeys {
			if strings.EqualFold(k, "host") {
				host = headers[k]
				break
			}
		}
	}

	result.Append(",transport=xhttp")
	var path interface{}
	if xhttp != nil {
		path = xhttp["path"]
	}
	for _, kv := range []struct {
		key string
		val interface{}
	}{{"path", path}, {"host", host}} {
		if kv.val == nil {
			continue
		}
		text, err := loonFormatValue(kv.val, false)
		if err != nil {
			return err
		}
		result.Append(fmt.Sprintf(",%s=%s", kv.key, text))
	}
	if xhttp != nil {
		for _, f := range loonXhttpFields {
			v, ok := xhttp[f[1]]
			if !ok || v == nil {
				continue
			}
			text, err := loonFormatValue(v, false)
			if err != nil {
				return err
			}
			result.Append(fmt.Sprintf(",xhttp-%s=%s", f[0], text))
		}
	}
	for _, k := range headerKeys {
		v := headers[k]
		if strings.EqualFold(k, "host") || v == nil {
			continue
		}
		text, err := loonFormatValue(k+": "+loonValueText(v), true)
		if err != nil {
			return err
		}
		result.Append(",xhttp-header=" + text)
	}
	return nil
}
