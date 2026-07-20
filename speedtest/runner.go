package main

import (
	"context"
	"crypto/tls"
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
	cfLatencyProbeURL   = "https://cp.cloudflare.com/generate_204" // 真延迟用 Cloudflare 204(全球边缘 + CDN 边)
	egressIPProbeURL    = "https://api.ipify.org"                  // 经代理回显出口 IP,用于核对出站链路是否符合预期
	mixedPort           = 17900                                    // 串行测速,固定端口即可
	cfLatencySamples    = 3                                        // 真延迟采样次数,取最快 2 个均值(去掉首包冷启动)
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
	TestDuration time.Duration // 测速时长(默认 8s):下载这么久,按真实字节/耗时算速率
	TestBytes    int64         // 可选下载上限(0=不限,纯按时长)
	Timeout      time.Duration
	Threads      int  // 并发下载线程数(<=1 单线程)
	BufSize      int  // 每次收发的 io/socket buffer 字节数(默认 1MB;clamp 见 clampSpeedTestParams)
	LatencyOnly  bool // true 仅测真连接延迟(Cloudflare 204 多采样)不跑大文件下载
}

// 测速 buffer / 线程的取值边界。峰值内存 ≈ BufSize × Threads,maxSpeedTotalMem 防家用测速端 OOM。
const (
	defaultBufSize   = 1 << 20   // 1MB(= 历史固定值,向后兼容)
	minBufSize       = 64 << 10  // 64KB
	maxBufSize       = 16 << 20  // 16MB
	maxSpeedThreads  = 64        // 并发下载线程上限
	maxSpeedTotalMem = 256 << 20 // BufSize×Threads 上限:超了缩 BufSize
)

// clampSpeedTestParams 归一 bufSize(字节)与 threads,并把 bufSize×threads 峰值内存收敛到 maxSpeedTotalMem 内。
// 0/越界回落默认(bufSize=1MB, threads=1)。
func clampSpeedTestParams(bufSize, threads int) (int, int) {
	if threads <= 0 {
		threads = 1
	}
	if threads > maxSpeedThreads {
		threads = maxSpeedThreads
	}
	if bufSize <= 0 {
		bufSize = defaultBufSize
	}
	if bufSize < minBufSize {
		bufSize = minBufSize
	}
	if bufSize > maxBufSize {
		bufSize = maxBufSize
	}
	if int64(bufSize)*int64(threads) > maxSpeedTotalMem {
		bufSize = maxSpeedTotalMem / threads
		if bufSize < minBufSize {
			bufSize = minBufSize
		}
	}
	return bufSize, threads
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

	egressIP := measureEgressIP(ctx)

	// LatencyOnly:只测真连接延迟(Cloudflare 204 多采样),不跑下载
	if opts.LatencyOnly {
		latency := measureLatencyCloudflare(ctx, cfLatencySamples)
		return Result{LatencyMs: latency, EgressIP: egressIP}, nil
	}

	latency := measureLatency(ctx)

	bufSize, threads := clampSpeedTestParams(opts.BufSize, opts.Threads)
	n, dur, err := downloadTimed(ctx, testURL, opts.TestDuration, opts.TestBytes, threads, bufSize)
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

// proxyClient 经 mihomo mixed-port 走代理的 HTTP 客户端。
// 单流测速调优:1MB ReadBufferSize / 禁 HTTP/2(单流被流控限速)/ 禁 Compression / 复用 Transport
func proxyClient() *http.Client {
	return &http.Client{Transport: sharedProxyTransport()}
}

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
)

// sharedProxyTransport 延迟/出口IP 探测用(小请求),默认 1MB 读缓冲即可,单例复用。
func sharedProxyTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransport = newProxyTransport(defaultBufSize)
	})
	return sharedTransport
}

// newProxyTransport 构造经 mihomo mixed-port 的 Transport。readBuf 决定 socket 读缓冲(降 read syscall 频率);
// 禁 HTTP/2(单流被流控限速)、禁压缩。下载测速按用户选的 bufSize per-call 构造。
func newProxyTransport(readBuf int) *http.Transport {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	if readBuf < minBufSize {
		readBuf = minBufSize
	}
	return &http.Transport{
		Proxy:              http.ProxyURL(proxyURL),
		ReadBufferSize:     readBuf,
		WriteBufferSize:    64 << 10,
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		TLSNextProto:       map[string]func(string, *tls.Conn) http.RoundTripper{}, // 显式禁 HTTP/2
		MaxIdleConns:       64,
		IdleConnTimeout:    90 * time.Second,
	}
}

// proxyClientBuf 下载测速用:按 bufSize 配 socket 读缓冲。
func proxyClientBuf(bufSize int) *http.Client {
	return &http.Client{Transport: newProxyTransport(bufSize)}
}

// getCopyBuf/putCopyBuf 自适应 io.CopyBuffer 缓冲池:cap>=size 复用,否则新建。
// 支持用户选的 1/4/8/16M 包大小(峰值内存 ≈ bufSize×threads,已由 clampSpeedTestParams 收敛)。
var copyBufPool sync.Pool

func getCopyBuf(size int) *[]byte {
	if v := copyBufPool.Get(); v != nil {
		b := v.(*[]byte)
		if cap(*b) >= size {
			*b = (*b)[:size]
			return b
		}
	}
	b := make([]byte, size)
	return &b
}

func putCopyBuf(b *[]byte) { copyBufPool.Put(b) }

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

// measureLatencyCloudflare 用 Cloudflare 204 多次采样,取最快 2 个均值;
// 首包受 TLS 握手 / mihomo cold-start 影响,平均后更接近"真连接延迟"。全部失败返回 -1。
func measureLatencyCloudflare(ctx context.Context, samples int) int64 {
	if samples <= 0 {
		samples = cfLatencySamples
	}
	client := proxyClient()
	client.Timeout = 8 * time.Second
	probes := make([]int64, 0, samples)
	for i := 0; i < samples; i++ {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfLatencyProbeURL, nil)
		if err != nil {
			continue
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		probes = append(probes, time.Since(start).Milliseconds())
	}
	if len(probes) == 0 {
		return -1
	}
	sortInt64Asc(probes)
	keep := 2
	if len(probes) < keep {
		keep = len(probes)
	}
	var sum int64
	for i := 0; i < keep; i++ {
		sum += probes[i]
	}
	return sum / int64(keep)
}

func sortInt64Asc(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func downloadTimed(ctx context.Context, dlURL string, dur time.Duration, maxBytes int64, threads, bufSize int) (int64, time.Duration, error) {
	dlCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	if threads <= 1 {
		return downloadSingle(dlCtx, dlURL, maxBytes, bufSize)
	}

	var wg sync.WaitGroup
	results := make([]int64, threads)
	errs := make([]error, threads)
	start := time.Now()
	for i := range threads {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n, _, e := downloadSingle(dlCtx, dlURL, maxBytes, bufSize)
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

func downloadSingle(ctx context.Context, dlURL string, maxBytes int64, bufSize int) (int64, time.Duration, error) {
	client := proxyClientBuf(bufSize)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 mmwx-speedtest/1.0")
	req.Header.Set("Accept-Encoding", "identity")
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
	buf := getCopyBuf(bufSize)
	defer putCopyBuf(buf)
	n, cerr := io.CopyBuffer(io.Discard, reader, *buf)
	elapsed := time.Since(start)
	if ctx.Err() == context.DeadlineExceeded || cerr == nil {
		return n, elapsed, nil
	}
	return n, elapsed, cerr
}
