// mmwx-speedtester:妙妙屋X 家用测速端(PRO speed_test Phase 2)。
// 部署在用户家里的服务器/电脑上,主动反向连接主控(解决家庭无公网 IP);
// 收到测速任务后用 mihomo 内核对指定节点下载测速,结果经同一连接回传。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
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

	log.Printf("[speedtester] %s 启动,连接 %s", *name, *master)
	backoff := time.Second
	for {
		if err := connectAndServe(wsURL, *name); err != nil {
			log.Printf("[speedtester] 连接断开: %v;%v 后重连", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func connectAndServe(wsURL, name string) error {
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("[speedtester] 已连接主控")

	var writeMu = make(chan struct{}, 1)
	writeMu <- struct{}{}
	send := func(m wsMsg) error {
		<-writeMu
		defer func() { writeMu <- struct{}{} }()
		data, _ := json.Marshal(m)
		return conn.WriteMessage(websocket.TextMessage, data)
	}

	_ = send(wsMsg{Type: "hello", Name: name})

	// 心跳保活
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(30 * time.Second)
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
		TestBytes: job.Bytes,
		TestURL:   job.URL,
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
