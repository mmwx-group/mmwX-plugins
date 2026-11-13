package proxyparser

import (
	"strconv"
	"strings"
)

// parseSurgeLine 解析 Surge INI 行(`Name = type, server, port, k=v, ...`)为 clash 节点。
// 目前支持 snell 与 ssh,其它类型返回 nil(与前端原 proxy-parser.ts 的语义一致);无法解析时返回 nil。
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
	for _, t := range splitSurgeParams(rest) {
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

	if typ != "snell" && typ != "ssh" {
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

	if typ == "ssh" {
		return surgeSSHNode(name, server, port, kv)
	}

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

// surgeSSHNode Surge `ssh` 行 → mihomo ssh 节点。
//
//	proxy = ssh, 1.2.3.4, 22, username=root, password=pw, idle-timeout=180, server-fingerprint="ssh-ed25519 AAAA…,ssh-rsa AAAA…"
//
// server-fingerprint 就是 known_hosts 去掉主机名那段,逗号分隔多把,对应 mihomo 的 host-key。
// 用 private-key=<钥匙串名> 的行引用的是配置里另一个段,单行解析拿不到私钥,只能跳过。
func surgeSSHNode(name, server string, port int, kv map[string]string) map[string]any {
	username := unquoteSurgeValue(kv["username"])
	password := unquoteSurgeValue(kv["password"])
	if username == "" || password == "" {
		return nil
	}
	node := map[string]any{
		"name":     name,
		"type":     "ssh",
		"server":   server,
		"port":     port,
		"username": username,
		"password": password,
		"udp":      false,
	}
	var keys []string
	for _, k := range strings.Split(unquoteSurgeValue(kv["server-fingerprint"]), ",") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) > 0 {
		node["host-key"] = keys
	}
	return node
}

// splitSurgeParams 按逗号切 Surge 行,双引号里的逗号不切(server-fingerprint 的多把公钥就是用逗号连起来的)。
func splitSurgeParams(s string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

// unquoteSurgeValue 去掉 Surge 参数值两边的双引号。
func unquoteSurgeValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}
