package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 中转抓取:主控把「抓这个 URL」的活派给测速端,用测速端自己的出口 IP 去取。
//
// 用途是导入外部订阅 —— 不少机场只允许大陆 IP 访问,而主控往往在海外。测速端本来
// 就常常部署在用户家里(大陆家宽),正好能当这个出口。
//
// **不经 mihomo**:要的就是测速端自己的 IP,套代理就失去意义了(与可达性探测同理)。

const (
	// fetchMaxBytes 单次抓取的响应体上限。订阅文件通常几十 KB,给到 16 MiB 已经很宽;
	// 不设上限的话,一个被攻破的主控可以让家用测速端去下载超大文件、把用户家宽跑满。
	fetchMaxBytes = 16 << 20
	fetchTimeout  = 45 * time.Second
)

// runFetch 处理主控派下来的抓取任务。
func runFetch(job wsMsg, send func(wsMsg) error) {
	log.Printf("[speedtester] 收到中转抓取任务 job=%s", job.JobID)
	fail := func(msg string) {
		_ = send(wsMsg{Type: "fetch_result", JobID: job.JobID, Status: "failed", Error: msg})
	}
	target := strings.TrimSpace(job.URL)
	if err := validateFetchTarget(target); err != nil {
		fail(err.Error())
		return
	}
	ua := strings.TrimSpace(job.UserAgent)
	if ua == "" {
		ua = "clash-meta/2.4.0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		fail("构造请求失败: " + err.Error())
		return
	}
	req.Header.Set("User-Agent", ua)

	resp, err := ssrfSafeClient(fetchTimeout).Do(req)
	if err != nil {
		fail("抓取失败: " + err.Error())
		return
	}
	defer resp.Body.Close()

	// 多读 1 字节用来判断是不是被截断 —— 截断的订阅解析出来是残缺节点列表,
	// 比直接失败更糟(用户会以为机场少给了节点)。
	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchMaxBytes+1))
	if err != nil {
		fail("读取响应失败: " + err.Error())
		return
	}
	if int64(len(body)) > fetchMaxBytes {
		fail(fmt.Sprintf("响应超过 %d MiB 上限", fetchMaxBytes>>20))
		return
	}

	// 只回传订阅需要的头。全量回传会把 Set-Cookie 之类的东西带回主控,没必要。
	headers := map[string]string{}
	for _, name := range []string{"subscription-userinfo", "content-disposition", "profile-update-interval", "content-type"} {
		if v := resp.Header.Get(name); v != "" {
			headers[name] = v
		}
	}
	_ = send(wsMsg{
		Type: "fetch_result", JobID: job.JobID, Status: "ok",
		StatusCode: resp.StatusCode,
		Headers:    headers,
		// base64:订阅可能是二进制(gzip / base64 变体),直接塞进 JSON 字符串会被
		// UTF-8 校验破坏内容。
		Body: base64.StdEncoding.EncodeToString(body),
	})
}

// validateFetchTarget 校验目标 URL。
func validateFetchTarget(raw string) error {
	if raw == "" {
		return errors.New("URL 为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("URL 无法解析")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("只允许 http/https")
	}
	if u.Host == "" {
		return errors.New("URL 缺少主机名")
	}
	return nil
}

// ssrfSafeClient 返回一个**在建连时**逐个校验目标 IP 的客户端。
//
// 测速端往往就跑在用户家里的路由器后面,主控让它抓什么它就抓什么。所以必须假设
// 「主控可能被攻破」:否则一条 http://192.168.1.1/ 就能把用户家里的内网设备
// 拿来当跳板,甚至读到云厂商的元数据服务(169.254.169.254)。
//
// 校验放在 DialContext 而不是解析 URL 时,是为了防 DNS rebinding —— 域名解析出来的
// 结果可以在校验和建连之间变化,只有在真正拨号的那一刻检查才作数。
func ssrfSafeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if !isPublicIP(ip.IP) {
						return nil, fmt.Errorf("拒绝连接非公网地址 %s", ip.IP)
					}
				}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				// 再查一次实际连上的对端:上面查的是解析结果,这里是既成事实。
				if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok && !isPublicIP(tcp.IP) {
					_ = conn.Close()
					return nil, fmt.Errorf("拒绝连接非公网地址 %s", tcp.IP)
				}
				return conn, nil
			},
			// 跟随跳转时每一跳都会重新走上面的 DialContext,所以重定向到内网同样会被拦。
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// isPublicIP 判断是否为可以对外访问的公网地址。
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// 云厂商元数据服务(169.254.169.254)已被 IsLinkLocalUnicast 覆盖。
	// 这里再补几段 IsPrivate 不认、但同样不该访问的:
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // 100.64.0.0/10 运营商级 NAT
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24 IETF 保留
			return false
		case v4[0] >= 240: // 240.0.0.0/4 保留
			return false
		}
	}
	return true
}
