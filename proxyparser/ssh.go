package proxyparser

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// SSH 节点(mihomo `type: ssh`)的链接形式。SSH 没有各客户端通用的分享链接,这里用
//
//	ssh://用户名:密码@服务器:端口?host-key=<公钥>#名称
//
// 用户名、密码、名称按 URI 规则百分号编码;host-key 是 known_hosts 里去掉主机名的那段
// (`ssh-ed25519 AAAA…`),可重复出现,也可以一个参数里用逗号分隔多把。端口缺省 22。
// 只支持密码认证:私钥放进链接既不安全也没有客户端这么用。
// 与 substore 的 URIProducer.encodeSSH 互为逆运算。

// hostKeyRawPlus 手写链接里没编码的 `ssh-ed25519+AAAA…`:类型与 base64 之间的空格被写成了 '+'。
var hostKeyRawPlus = regexp.MustCompile(`^((?:ssh|ecdsa|sk)-[A-Za-z0-9@.-]+)\+(AAAA)`)

func parseSSHURL(uri string) (map[string]any, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid ssh url: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("invalid ssh url: missing username")
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return nil, fmt.Errorf("invalid ssh url: missing password")
	}
	server := u.Hostname()
	if server == "" {
		return nil, fmt.Errorf("invalid ssh url: missing server")
	}
	port := 22
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid ssh url: bad port %q", p)
		}
		port = n
	}
	name := u.Fragment
	if name == "" {
		name = "SSH Node"
	}

	node := map[string]any{
		"name":     name,
		"type":     "ssh",
		"server":   server,
		"port":     port,
		"username": u.User.Username(),
		"password": password,
		"udp":      false,
	}
	if keys := parseSSHHostKeys(u.RawQuery); len(keys) > 0 {
		node["host-key"] = keys
	}
	return node, nil
}

// parseSSHHostKeys 取出所有 host-key 参数。不用 url.Query():它把 '+' 当空格,
// 而公钥的 base64 里本来就有 '+'。这里按路径规则解码('+' 保持原样,%20 才是空格)。
func parseSSHHostKeys(rawQuery string) []string {
	var keys []string
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		if key, err := url.PathUnescape(k); err != nil || strings.ToLower(key) != "host-key" {
			continue
		}
		val, err := url.PathUnescape(v)
		if err != nil {
			continue
		}
		for _, one := range strings.Split(val, ",") {
			one = strings.TrimSpace(one)
			if one == "" {
				continue
			}
			if !strings.Contains(one, " ") {
				one = hostKeyRawPlus.ReplaceAllString(one, "$1 $2")
			}
			keys = append(keys, one)
		}
	}
	return keys
}
