package proxyparser

import (
	"strconv"
	"strings"
)

// parseSurgeLine 解析 Surge INI 行(`Name = type, server, port, k=v, ...`)为 clash 节点。
// 目前仅支持 snell —— 与前端原 proxy-parser.ts parseSurgeLine/toClashProxy 的行为一致
// (其它类型的 Surge 行历史上即返回 nil,这里保持同样语义);无法解析时返回 nil。
func parseSurgeLine(line string) map[string]any {
	eqIdx := strings.Index(line, "=")
	if eqIdx == -1 {
		return nil
	}
	name := strings.TrimSpace(line[:eqIdx])
	rest := strings.TrimSpace(line[eqIdx+1:])
	if name == "" || rest == "" {
		return nil
	}

	tokens := make([]string, 0)
	for _, t := range strings.Split(rest, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) < 3 {
		return nil
	}

	typ := strings.ToLower(tokens[0])
	server := tokens[1]
	port, err := strconv.Atoi(tokens[2])
	if err != nil || server == "" || port <= 0 {
		return nil
	}

	// 仅实现 snell(其它类型按 Surge 同款字段后续按需扩展)
	if typ != "snell" {
		return nil
	}

	kv := map[string]string{}
	for i := 3; i < len(tokens); i++ {
		t := tokens[i]
		ei := strings.Index(t, "=")
		if ei == -1 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(t[:ei]))
		if k == "" {
			continue
		}
		kv[k] = strings.TrimSpace(t[ei+1:])
	}
	truthy := func(v string) bool { return v == "true" || v == "1" || v == "yes" }

	version := 4
	if v := kv["version"]; v != "" {
		if n, e := strconv.Atoi(v); e == nil && n != 0 {
			version = n
		}
	}

	node := map[string]any{
		"name":    name,
		"type":    "snell",
		"server":  server,
		"port":    port,
		"psk":     kv["psk"],
		"version": version,
	}
	// obfs-opts(Snell 2/3):Surge `obfs = http/tls` + `obfs-host = ...`
	if obfs := kv["obfs"]; obfs != "" && obfs != "none" {
		host := kv["obfs-host"]
		if host == "" {
			host = kv["obfs-hostname"]
		}
		node["obfs-opts"] = map[string]any{
			"mode": obfs,
			"host": host,
		}
	}
	if truthy(kv["tfo"]) {
		node["tfo"] = true
	}
	if truthy(kv["udp-relay"]) || truthy(kv["udp"]) {
		node["udp"] = true
	}
	if truthy(kv["reuse"]) { // Snell 4+
		node["reuse"] = true
	}
	return node
}
