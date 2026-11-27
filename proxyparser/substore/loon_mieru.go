package substore

import (
	"fmt"
	"strconv"
	"strings"
)

// mieru Loon 的 Mieru 节点,跟上游 Sub-Store 85948dcf(2026-11-23):
//
//	名称=mieru,服务器,端口,"用户名","密码"[,udp=true][,block-quic=..][,ip-mode=..]
//
// Loon 只支持 TCP 传输、单个端口,没有 multiplexing / handshake-mode / mtu / traffic-pattern 选项
// (上游同样不输出);UDP 传输、TLS / REALITY 报错跳过。用户名、密码各 1–64 个 UTF-8 字节。
// 从前 Loon producer 没有 mieru 分支,Mieru 节点在 Loon 订阅里一律被跳过。
func (p *LoonProducer) mieru(proxy Proxy) (string, error) {
	if transport := strings.TrimSpace(GetAnyString(proxy, "transport")); transport != "" && !strings.EqualFold(transport, "TCP") {
		return "", fmt.Errorf("Loon Mieru requires TCP transport")
	}
	if GetBool(proxy, "tls") || GetMap(proxy, "reality-opts") != nil {
		return "", fmt.Errorf("Loon Mieru does not support TLS or REALITY")
	}
	server := strings.TrimSpace(GetString(proxy, "server"))
	if server == "" {
		return "", fmt.Errorf("Loon Mieru requires a server")
	}
	portText := strings.TrimSpace(loonValueText(proxy["port"]))
	if !IsPresent(proxy, "port") {
		// 端口范围节点只带 port-range(mihomo 不许 port 与 port-range 同写,妙妙屋X 下发前会删掉 port)。
		// Loon 只有单个端口:取范围的第一个端口,服务端整个范围都在监听。
		first, _, _ := strings.Cut(GetAnyString(proxy, "port-range"), ",")
		first, _, _ = strings.Cut(first, "-")
		portText = strings.TrimSpace(first)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strings.Trim(portText, "0123456789") != "" {
		return "", fmt.Errorf("Loon Mieru port must be an integer from 1 to 65535")
	}

	var creds [2]string
	for i, key := range []string{"username", "password"} {
		v := GetAnyString(proxy, key)
		if v == "" || len(v) > 64 {
			return "", fmt.Errorf("Loon Mieru username and password must each be 1-64 UTF-8 bytes")
		}
		if creds[i], err = loonFormatValue(v, true); err != nil {
			return "", err
		}
	}

	if IsIPv6(server) {
		server = "[" + server + "]"
	}
	result := NewResult(proxy)
	result.Append(fmt.Sprintf("%s=mieru,%s,%d,%s,%s", GetString(proxy, "name"), server, port, creds[0], creds[1]))
	if GetBool(proxy, "udp") {
		result.Append(",udp=true")
	}
	p.appendBlockQuic(result, proxy)
	p.appendIPVersion(result, proxy)
	return result.String(), nil
}
