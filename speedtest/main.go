// mmwx-speedtester:妙妙屋X 家用测速端(PRO speed_test Phase 2)。
// 部署在用户家里的服务器/电脑上,主动反向连接主控(解决家庭无公网 IP);
// 收到测速任务后用 mihomo 内核对指定节点下载测速,结果经同一连接回传。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type wsMsg struct {
	Type        string  `json:"type"`
	JobID       string  `json:"job_id,omitempty"`
	ClashConfig string  `json:"clash_config,omitempty"`
	Bytes       int64   `json:"bytes,omitempty"`
	URL         string  `json:"url,omitempty"`
	Threads     int     `json:"threads,omitempty"`
	LatencyOnly bool    `json:"latency_only,omitempty"` // true 仅测真连接延迟(Cloudflare 204)
	DownMbps    float64 `json:"down_mbps,omitempty"`
	LatencyMs   int64   `json:"latency_ms,omitempty"`
	EgressIP    string  `json:"egress_ip,omitempty"`
	Status      string  `json:"status,omitempty"`
	Error       string  `json:"error,omitempty"`
	Name        string  `json:"name,omitempty"`
}

func main() {
	master := flag.String("master", envOr("MMWX_MASTER", ""), "主控地址,如 https://x.miaomiaowu.net")
	token := flag.String("token", envOr("MMWX_SPEEDTEST_TOKEN", ""), "测速端配对令牌(主控插件页生成)")
	name := flag.String("name", envOr("MMWX_SPEEDTEST_NAME", "home-tester"), "测速端名称(展示用)")
	flag.Parse()

	if *master == "" || *token == "" {
		log.Fatal("必须提供 -master 和 -token(或环境变量 MMWX_MASTER / MMWX_SPEEDTEST_TOKEN)")
	}
	wsURL, err := buildWSURL(*master, *token)
	if err != nil {
		log.Fatalf("解析 master 地址失败: %v", err)
	}

	// 预热:确保 mihomo 可用(没有则自动下载)。
	if _, err := EnsureMihomo(context.Background()); err != nil {
		log.Printf("[warn] mihomo 预热失败(测速时会重试): %v", err)
	}

	log.Printf("[speedtester] %s 启动,主控=%s", *name, *master)
	log.Printf("[speedtester] 拨号目标 %s", maskedURL(wsURL))

	// 指数退避重连:1s → 2s → 4s ... 封顶 60s。connectAndServe 内每次成功握手后会通过
	// resetBackoff 函数把它重置回 1s — 防止"一次断网长时间后,网恢复了仍要等 60s 才重连"。
	backoff := time.Second
	const maxBackoff = 60 * time.Second
	resetBackoff := func() { backoff = time.Second }
	for {
		err := connectAndServe(wsURL, *name, resetBackoff)
		if err != nil {
			log.Printf("[speedtester] 连接断开: %v;%v 后重连", err, backoff)
		} else {
			// 正常 return 大概率不会发生(内部 for-loop 只在 read error 时 return),
			// 真发生也按短间隔重连
			log.Printf("[speedtester] 连接结束;%v 后重连", backoff)
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// maskedURL 隐藏 query 里的 token,避免日志泄露配对令牌。
func maskedURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	q := u.Query()
	if tok := q.Get("token"); tok != "" {
		if len(tok) > 8 {
			q.Set("token", tok[:4]+"…"+tok[len(tok)-4:])
		} else {
			q.Set("token", "***")
		}
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// 心跳节奏 + 读超时设计:
//   - 客户端每 30s 发一次应用层 ping(wsMsg{type:"ping"}),主控应回 pong
//   - 同时挂 WebSocket 协议层 PongHandler,主控也可主动 ping 我们 → 我们回 pong
//   - SetReadDeadline 设为 75s(2.5 × 30s 心跳间隔,容忍 1 次 pong 丢)
//   - 收到任何消息(text / pong)都刷新 read deadline → 真没消息才会触发超时
//
// 这样既能检测主动死亡(对端崩 / NAT keepalive 失效 / 网线被拔),又不会因为偶发卡顿就误判断开。
const (
	heartbeatInterval = 30 * time.Second
	readDeadline      = 75 * time.Second
)

func connectAndServe(wsURL, name string, onConnected func()) error {
	log.Printf("[speedtester] 正在拨号主控 WebSocket(15s 超时)...")
	// DefaultDialer 没有 HandshakeTimeout,DNS / TCP 阻塞时会一直挂没反馈;
	// 这里显式 15s 超时 + 失败时把 HTTP 状态码也打出来,便于区分:
	//   - "no such host" → 主控 URL 域名错或 DNS 不通
	//   - "connection refused" → 主控不在该地址监听
	//   - "HTTP 401" → token 错或已过期
	//   - "HTTP 404" → 主控版本太老,没有 /api/speedtest/tester/ws 端点
	dialer := &websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
	}
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		extra := ""
		if resp != nil {
			extra = fmt.Sprintf(" (HTTP %d %s)", resp.StatusCode, http.StatusText(resp.StatusCode))
		}
		log.Printf("[speedtester] ✗ 拨号失败: %v%s", err, extra)
		return err
	}
	defer conn.Close()
	log.Printf("[speedtester] ✓ 已连接主控,发送 hello")
	if onConnected != nil {
		onConnected() // 重置 backoff,下次断开从 1s 重新开始
	}

	// 初始读超时 — 服务端必须在 readDeadline 内有任何消息(包括 pong),否则强制断
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	// 收到协议层 pong 也算"活着" — 把 deadline 续上
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
		return nil
	})

	var writeMu = make(chan struct{}, 1)
	writeMu <- struct{}{}
	send := func(m wsMsg) error {
		<-writeMu
		defer func() { writeMu <- struct{}{} }()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		data, _ := json.Marshal(m)
		return conn.WriteMessage(websocket.TextMessage, data)
	}

	_ = send(wsMsg{Type: "hello", Name: name})

	// 心跳保活 — 应用层 ping(主控收到回 pong 一样会续 deadline)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if send(wsMsg{Type: "ping"}) != nil {
					return
				}
			}
		}
	}()

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		// 收到任何 text 帧都算活着,续 deadline
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
		var msg wsMsg
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if msg.Type == "run" {
			go runJob(msg, send)
		}
		// pong 等忽略
	}
}

func runJob(job wsMsg, send func(wsMsg) error) {
	log.Printf("[speedtester] 收到测速任务 job=%s", job.JobID)
	bin, err := EnsureMihomo(context.Background())
	if err != nil {
		_ = send(wsMsg{Type: "result", JobID: job.JobID, Status: "failed", Error: "mihomo 不可用: " + err.Error()})
		return
	}
	res, terr := RunNodeTest(context.Background(), bin, job.ClashConfig, Options{
		TestBytes:   job.Bytes,
		TestURL:     job.URL,
		Threads:     job.Threads,
		LatencyOnly: job.LatencyOnly,
	})
	out := wsMsg{Type: "result", JobID: job.JobID, LatencyMs: res.LatencyMs, EgressIP: res.EgressIP}
	if terr != nil {
		out.Status = "failed"
		out.Error = terr.Error()
	} else {
		out.Status = "ok"
		out.DownMbps = res.DownMbps
	}
	if err := send(out); err != nil {
		log.Printf("[speedtester] 回传结果失败: %v", err)
		return
	}
	log.Printf("[speedtester] job=%s 完成 status=%s down=%.1fMbps", job.JobID, out.Status, out.DownMbps)
}

// buildWSURL 把 http(s) 主控地址转成 ws(s) 的测速端连接 URL。
func buildWSURL(master, token string) (string, error) {
	u, err := url.Parse(strings.TrimRight(master, "/"))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
		// 已是 ws
	default:
		u.Scheme = "wss"
	}
	u.Path = "/api/speedtest/tester/ws"
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
