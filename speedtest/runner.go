package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultTestURL      = "https://dl.google.com/dl/android/studio/install/3.4.1.0/android-studio-ide-183.5522156-windows.exe"
	defaultTestDuration = 8 * time.Second
	latencyProbeURL     = "https://www.gstatic.com/generate_204"
	egressIPProbeURL    = "https://api.ipify.org" // 经代理回显出口 IP,用于核对出站链路是否符合预期
	mixedPort           = 17900                   // 串行测速,固定端口即可
)

// runMu 串行化测速:一次只跑一个节点,避免并发抢带宽导致结果失真。
var runMu sync.Mutex

// Result 单节点测速结果。
type Result struct {
	DownMbps  float64
	LatencyMs int64
	Bytes     int64
	Duration  time.Duration
	EgressIP  string
}

// Options 测速参数(留空用默认)。
type Options struct {
	TestURL      string        // 测试下载 URL(默认大文件)
	TestDuration time.Duration // 测速时长(默认 10s):下载这么久,按真实字节/耗时算速率
	TestBytes    int64         // 可选下载上限(0=不限,纯按时长)
	Timeout      time.Duration
	Threads      int // 并发下载线程数(<=1 单线程)
}

// RunNodeTest 用 mihomo 起单节点代理,测延迟 + 下行吞吐。clashConfigJSON 是 node.ClashConfig。
func RunNodeTest(ctx context.Context, mihomoBin, clashConfigJSON string, opts Options) (Result, error) {
	runMu.Lock()
	defer runMu.Unlock()

	if opts.TestDuration <= 0 {
		opts.TestDuration = defaultTestDuration
	}
	testURL := opts.TestURL
	if testURL == "" {
		testURL = defaultTestURL // 固定大文件,下载满测速时长即停
	}
	if opts.Timeout <= 0 {
		opts.Timeout = opts.TestDuration + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var proxy map[string]any
	if err := json.Unmarshal([]byte(clashConfigJSON), &proxy); err != nil {
		return Result{}, fmt.Errorf("解析节点 clash 配置失败: %w", err)
	}
	name, _ := proxy["name"].(string)
	if name == "" {
		name = "node"
		proxy["name"] = name
	}

	mini := map[string]any{
		"mixed-port":          mixedPort,
		"allow-lan":           false,
		"mode":                "rule",
		"log-level":           "warning",
		"external-controller": "127.0.0.1:0",
		"proxies":             []map[string]any{proxy},
		"proxy-groups": []map[string]any{
			{"name": "PROXY", "type": "select", "proxies": []string{name}},
		},
		"rules": []string{"MATCH,PROXY"},
	}
	cfg, err := yaml.Marshal(mini)
	if err != nil {
		return Result{}, err
	}

	workdir := filepath.Join("data", "speedtest-tmp", fmt.Sprintf("%d", time.Now().UnixNano()))
	stop, err := startMihomo(mihomoBin, workdir, cfg)
	if err != nil {
		return Result{}, err
	}
	defer func() { stop(); os.RemoveAll(workdir) }()

	latency := measureLatency(ctx)
	egressIP := measureEgressIP(ctx)

	threads := opts.Threads
	if threads <= 1 {
		threads = 1
	}
	n, dur, err := downloadTimed(ctx, testURL, opts.TestDuration, opts.TestBytes, threads)
	if err != nil {
		return Result{LatencyMs: latency, EgressIP: egressIP}, fmt.Errorf("下载测速失败: %w", err)
	}
	mbps := 0.0
	if dur > 0 {
		mbps = float64(n) * 8 / dur.Seconds() / 1e6
	}
	return Result{DownMbps: mbps, LatencyMs: latency, Bytes: n, Duration: dur, EgressIP: egressIP}, nil
}

// measureEgressIP 经代理请求一个 IP 回显端点,拿到出口 IP;失败返回空。
func measureEgressIP(ctx context.Context) string {
	client := proxyClient()
	client.Timeout = 8 * time.Second
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, egressIPProbeURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(buf))
	if len(ip) < 3 || len(ip) > 45 || (!strings.Contains(ip, ".") && !strings.Contains(ip, ":")) {
		return ""
	}
	return ip
}

func startMihomo(bin, workdir string, cfg []byte) (func(), error) {
	if err := os.MkdirAll(workdir, 0755); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(workdir, "config.yaml")
	if err := os.WriteFile(cfgPath, cfg, 0644); err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-d", workdir, "-f", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", mixedPort)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := (&net.Dialer{Timeout: 500 * time.Millisecond}).Dial("tcp", addr); derr == nil {
			c.Close()
			var once sync.Once
			return func() {
				once.Do(func() {
					done := make(chan error, 1)
					go func() { done <- cmd.Wait() }()
					// Windows 不支持向子进程发 SIGTERM,直接 Kill;其它平台先优雅 SIGTERM 再兜底 Kill。
					if runtime.GOOS == "windows" {
						_ = cmd.Process.Kill()
					} else {
						_ = cmd.Process.Signal(syscall.SIGTERM)
					}
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						_ = cmd.Process.Kill()
						<-done
					}
				})
			}, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return nil, fmt.Errorf("mihomo 启动超时(端口 %d 15s 内未就绪)", mixedPort)
}

func proxyClient() *http.Client {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

// measureLatency 经代理 GET 一个 204 端点,返回毫秒;失败返回 -1。
func measureLatency(ctx context.Context) int64 {
	client := proxyClient()
	client.Timeout = 10 * time.Second
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latencyProbeURL, nil)
	if err != nil {
		return -1
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return time.Since(start).Milliseconds()
}

func downloadTimed(ctx context.Context, dlURL string, dur time.Duration, maxBytes int64, threads int) (int64, time.Duration, error) {
	dlCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	if threads <= 1 {
		return downloadSingle(dlCtx, dlURL, maxBytes)
	}

	var wg sync.WaitGroup
	results := make([]int64, threads)
	errs := make([]error, threads)
	start := time.Now()
	for i := range threads {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n, _, e := downloadSingle(dlCtx, dlURL, maxBytes)
			results[idx] = n
			errs[idx] = e
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	var total int64
	var firstErr error
	for i := range threads {
		total += results[i]
		if errs[i] != nil && firstErr == nil {
			firstErr = errs[i]
		}
	}
	if total > 0 {
		return total, elapsed, nil
	}
	return 0, elapsed, firstErr
}

func downloadSingle(ctx context.Context, dlURL string, maxBytes int64) (int64, time.Duration, error) {
	client := proxyClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 mmwx-speedtest/1.0")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, maxBytes)
	}
	n, cerr := io.Copy(io.Discard, reader)
	elapsed := time.Since(start)
	if ctx.Err() == context.DeadlineExceeded || cerr == nil {
		return n, elapsed, nil
	}
	return n, elapsed, cerr
}
