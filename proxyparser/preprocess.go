package proxyparser

import (
	"encoding/base64"
	"strings"
)

// ContentKind 表示订阅内容的类型。
type ContentKind int

const (
	ContentUnknown ContentKind = iota
	ContentHTML
	ContentClashYAML // 含 proxies: 的 Clash YAML（由调用方自行解析 YAML）
	ContentURIList   // 每行一个 URI（已由本包解析为 proxies）
)

// supportedSchemes 是 Parse 能识别的全部 URI scheme 前缀。
var supportedSchemes = []string{
	"vmess://", "vless://", "ss://", "ssr://", "trojan://",
	"hysteria://", "hysteria2://", "hy2://", "tuic://",
	"socks://", "socks5://", "http://", "https://",
	"wireguard://", "wg://", "anytls://",
	"naive://", "naive+https://", "naive+http://", "mieru://", "snell://",
}

// SupportedSchemes 返回支持的 URI scheme 前缀（副本）。
func SupportedSchemes() []string {
	out := make([]string, len(supportedSchemes))
	copy(out, supportedSchemes)
	return out
}

// IsSupportedURI 判断一行是否以受支持的协议 scheme 开头。
func IsSupportedURI(line string) bool {
	line = strings.TrimSpace(line)
	for _, s := range supportedSchemes {
		if strings.HasPrefix(line, s) {
			return true
		}
	}
	return false
}

// isURIList 第一个非空行是受支持 URI 即认为是 URI 列表。
func isURIList(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return IsSupportedURI(line)
	}
	return false
}

// tryBase64Decode 尝试多种 base64 编码方式解码，全部失败返回 nil。
func tryBase64Decode(content string) []byte {
	content = strings.TrimSpace(content)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(content); err == nil {
			return decoded
		}
	}
	return nil
}

// DetectContentType 判定订阅内容类型（不解析 YAML，只看特征字符串）。
func DetectContentType(content []byte) ContentKind {
	trimmed := strings.TrimSpace(string(content))
	if strings.HasPrefix(trimmed, "<!DOCTYPE html>") || strings.HasPrefix(trimmed, "<html") {
		return ContentHTML
	}
	if strings.Contains(trimmed, "proxies:") {
		return ContentClashYAML
	}
	if isURIList(trimmed) {
		return ContentURIList
	}
	if decoded := tryBase64Decode(trimmed); decoded != nil {
		dt := strings.TrimSpace(string(decoded))
		if strings.Contains(dt, "proxies:") {
			return ContentClashYAML
		}
		if isURIList(dt) {
			return ContentURIList
		}
	}
	return ContentUnknown
}

// Preprocess 预处理订阅原始字节，替代 provider serve 的 preprocessSubscriptionContent 的 URI/base64 部分。
//   - URI 列表（含 base64 编码的）→ 解析为 proxies 返回，kind=ContentURIList。
//   - Clash YAML（含 base64 编码的）→ decoded 为明文 YAML 字节交调用方解析，kind=ContentClashYAML。
//   - HTML/未知 → proxies=nil，decoded=原内容（或 base64 解码后的字节）。
//
// 注意：module 不依赖 yaml，ClashYAML 的实际解析由调用方完成。
func Preprocess(content []byte) (proxies []map[string]any, kind ContentKind, decoded []byte, err error) {
	trimmed := strings.TrimSpace(string(content))

	if strings.HasPrefix(trimmed, "<!DOCTYPE html>") || strings.HasPrefix(trimmed, "<html") {
		return nil, ContentHTML, content, nil
	}
	if strings.Contains(trimmed, "proxies:") {
		return nil, ContentClashYAML, content, nil
	}
	if isURIList(trimmed) {
		ps, e := ParseSubscription(trimmed)
		return ps, ContentURIList, content, e
	}
	if dec := tryBase64Decode(trimmed); dec != nil {
		dt := strings.TrimSpace(string(dec))
		if strings.Contains(dt, "proxies:") {
			return nil, ContentClashYAML, dec, nil
		}
		if isURIList(dt) {
			ps, e := ParseSubscription(dt)
			return ps, ContentURIList, dec, e
		}
		return nil, ContentUnknown, dec, nil
	}
	return nil, ContentUnknown, content, nil
}
