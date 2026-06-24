package proxyparser

import "strings"

// skipCertVerifyAliases 是 skip-cert-verify 在各客户端/分享链接里的所有已知写法。
var skipCertVerifyAliases = []string{
	"insecure", "allowInsecure", "allow_insecure",
	"skip-cert-verify", "skip_cert_verify", "skipCertVerify",
}

// truthy 判断 query 值是否表示"真"。
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// boolFromAliases 按 keys 顺序在 params 查找:任一别名存在且为真 → (true,true);
// 存在但全为假 → (false,true);全部不存在 → (false,false)。
func boolFromAliases(params map[string]string, keys ...string) (val bool, present bool) {
	for _, k := range keys {
		if v, ok := params[k]; ok {
			present = true
			if truthy(v) {
				return true, true
			}
		}
	}
	return false, present
}

// skipCertVerify 解析 skip-cert-verify 的全部别名。
func skipCertVerify(params map[string]string) (val bool, present bool) {
	return boolFromAliases(params, skipCertVerifyAliases...)
}

// firstNonEmpty 返回 params 中按 keys 顺序第一个非空值。
func firstNonEmpty(params map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := params[k]; v != "" {
			return v
		}
	}
	return ""
}
