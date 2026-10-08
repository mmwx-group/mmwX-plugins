// Package speedtest 在主控本机用 mihomo 内核对节点测速(PRO 功能 speed_test 的 Phase 1)。
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const mihomoCacheDir = "data/bin"

// minMihomoVersion:snell v4/v5 支持自 mihomo v1.19.26 起(v1.19.25 及更早会报 "snell version error: 4")。
// 定位到的 mihomo 若低于此版本则跳过、重新下载最新,确保能对 snell 节点测速。
const minMihomoVersion = "1.19.26"

var mihomoVerRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// mihomoVersion 运行 `<bin> -v` 解析出 "X.Y.Z";解析不到返回 ""。
func mihomoVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	m := mihomoVerRe.FindStringSubmatch(string(out))
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// versionGTE 比较点分版本 a >= b(仅比 X.Y.Z 前三段)。
func versionGTE(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return true
}

// mihomoSupportsSnell 检查 mihomo 版本 >= minMihomoVersion(确保支持 snell v4/v5)。
// 版本解析不到时保守返回 true,不误伤非标准但可用的二进制。
func mihomoSupportsSnell(bin string) bool {
	v := mihomoVersion(bin)
	if v == "" {
		return true
	}
	return versionGTE(v, minMihomoVersion)
}

// miuCoreRepo:带 Miu 协议出站的 mihomo(源码在公开仓 mmwx-group/meowC 的 core/Clash.Meta)
// 的预编译包发在这个仓库,tag 形如 mihomo-miu-<版本>,资源名 mihomo-miu-<os>-<arch>.gz。
// 官方 mihomo 不认 type: miu,测 Miu 节点必须用这份。
const (
	miuCoreRepo      = "mmwx-group/mmwX-plugins"
	miuCoreTagPrefix = "mihomo-miu-"
)

// mihomoSupportsMiu 看 `<bin> -v` 的输出里有没有 miu 标记(我们的构建把版本号写成 miu-<提交>)。
func mihomoSupportsMiu(bin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	return strings.Contains(strings.ToLower(string(out)), "miu")
}

// mihomoBinName 平台相关的 mihomo 可执行文件名(Windows 带 .exe)。
func mihomoBinName() string {
	if runtime.GOOS == "windows" {
		return "mihomo.exe"
	}
	return "mihomo"
}

var (
	mihomoMu   sync.Mutex // 串行化定位/下载,避免并发重复下载
	cachedPath string
)

// EnsureMihomo 返回可用的 mihomo 二进制路径;按序尝试:env MIHOMO_BIN → data/bin/mihomo →
// $PATH → 自动下载到 data/bin/mihomo。
//
// 优先要带 Miu 的内核:本地缓存 / $PATH 里的不带 Miu 就先去下我们的包;下不到(还没发布、
// 没有当前平台的包、网络不通)再退回原来的路子 —— 用现成的官方内核或下官方最新,此时除 Miu
// 以外的节点照常能测。MIHOMO_BIN 是用户明确指定的,不替他换。
func EnsureMihomo(ctx context.Context) (string, error) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()

	if cachedPath != "" && fileExists(cachedPath) {
		return cachedPath, nil
	}
	// 每个候选都要求版本支持 snell(>= minMihomoVersion),否则跳过、最终重新下载最新。
	if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
		cachedPath = p
		return p, nil
	}
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	localOK := fileExists(local) && mihomoSupportsSnell(local)
	if localOK && mihomoSupportsMiu(local) {
		cachedPath = local
		return local, nil
	}
	pathBin, perr := exec.LookPath("mihomo")
	pathOK := perr == nil && mihomoSupportsSnell(pathBin)
	if pathOK && mihomoSupportsMiu(pathBin) {
		cachedPath = pathBin
		return pathBin, nil
	}
	if err := downloadMiuMihomo(ctx, local); err == nil {
		cachedPath = local
		return local, nil
	} else {
		log.Printf("[warn] 带 Miu 的 mihomo 下载失败,先用官方内核(Miu 节点暂时测不了),后台每 10 分钟重试: %v", err)
		miuRetryOnce.Do(func() { go retryMiuDownload(local) })
	}
	if localOK {
		cachedPath = local
		return local, nil
	}
	if pathOK {
		cachedPath = pathBin
		return pathBin, nil
	}
	// 自动下载最新(支持 snell)。若 data/bin 里是旧版会被覆盖。
	if err := downloadMihomo(ctx, local); err != nil {
		return "", fmt.Errorf("mihomo 不可用且自动下载失败: %w", err)
	}
	cachedPath = local
	return local, nil
}

var miuRetryOnce sync.Once

// retryMiuDownload 首次没下到带 Miu 的内核时在后台接着试,下到就换上(之后的测速直接用新的)。
func retryMiuDownload(local string) {
	for {
		time.Sleep(10 * time.Minute)
		mihomoMu.Lock()
		err := downloadMiuMihomo(context.Background(), local)
		if err == nil {
			cachedPath = local
		}
		mihomoMu.Unlock()
		if err == nil {
			log.Printf("[speedtester] 带 Miu 的 mihomo 内核已就绪: %s", local)
			return
		}
		log.Printf("[warn] 带 Miu 的 mihomo 仍未下到: %v", err)
	}
}

// MihomoStatus 报告 mihomo 是否就绪及来源(供 UI 展示)。
func MihomoStatus() (ready bool, path string) {
	if cachedPath != "" && fileExists(cachedPath) {
		return true, cachedPath
	}
	// 仅当版本支持 snell 时才算就绪,否则报未就绪以触发下载最新。
	if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
		return true, p
	}
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	if fileExists(local) && mihomoSupportsSnell(local) {
		return true, local
	}
	if p, err := exec.LookPath("mihomo"); err == nil && mihomoSupportsSnell(p) {
		return true, p
	}
	return false, ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// downloadMihomo 从 MetaCubeX/mihomo 最新 release 下载匹配当前平台的 .gz 单二进制,解压到 dst。
func downloadMihomo(ctx context.Context, dst string) error {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	// amd64 用 compatible 变体以兼容老 CPU;其余直接用 goarch。
	archToken := goarch
	if goarch == "amd64" {
		archToken = "amd64-compatible"
	}

	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		return err
	}
	// Windows release 是 .zip(内含 .exe);其它平台是 .gz(单二进制)。
	ext := ".gz"
	if goos == "windows" {
		ext = ".zip"
	}
	pick := func(arch string) (string, string) {
		p := fmt.Sprintf("mihomo-%s-%s-", goos, arch)
		for _, a := range rel.Assets {
			if strings.HasPrefix(a.Name, p) && strings.HasSuffix(a.Name, ext) {
				return a.BrowserDownloadURL, a.Name
			}
		}
		return "", ""
	}
	assetURL, assetName := pick(archToken)
	if assetURL == "" && goarch == "amd64" {
		assetURL, assetName = pick("amd64") // 回退普通 amd64
	}
	if assetURL == "" {
		return fmt.Errorf("未找到匹配 %s/%s 的 mihomo release 资源", goos, archToken)
	}

	return downloadMihomoAsset(ctx, assetURL, assetName, dst)
}

// pickMiuAsset 在一批 release 里找最新的 mihomo-miu-* 里匹配平台的资源(列表接口按时间倒序)。
func pickMiuAsset(rels []ghRelease, goos, goarch string) (url, name string) {
	want := fmt.Sprintf("mihomo-miu-%s-%s.gz", goos, goarch)
	for _, rel := range rels {
		if !strings.HasPrefix(rel.TagName, miuCoreTagPrefix) {
			continue
		}
		for _, a := range rel.Assets {
			if a.Name == want {
				return a.BrowserDownloadURL, a.Name
			}
		}
	}
	return "", ""
}

// downloadMiuMihomo 下载带 Miu 的 mihomo 到 dst。各平台都是 .gz 单二进制。
func downloadMiuMihomo(ctx context.Context, dst string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+miuCoreRepo+"/releases?per_page=30", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "miaomiaowux-speedtest")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("查询 release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("查询 release HTTP %d", resp.StatusCode)
	}
	var rels []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rels); err != nil {
		return err
	}
	assetURL, assetName := pickMiuAsset(rels, runtime.GOOS, runtime.GOARCH)
	if assetURL == "" {
		return fmt.Errorf("没有匹配 %s/%s 的 mihomo-miu 包", runtime.GOOS, runtime.GOARCH)
	}
	return downloadMihomoAsset(ctx, assetURL, assetName, dst)
}

// downloadMihomoAsset 下载一个 release 资源并解到 dst:.zip 取其中的 .exe,其余按 .gz 单二进制。
func downloadMihomoAsset(ctx context.Context, assetURL, assetName, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	log.Printf("[speedtester] 下载内核 %s ...", assetName)
	dl := dst + ".dl"
	defer os.Remove(dl)
	if err := fetchWithResume(ctx, assetURL, dl); err != nil {
		// 自带的下载器连不上时换系统的 curl / wget 再试:有的路由器上(透明代理、中间盒)
		// Go 的 HTTPS 连接建不起来(Get ...: EOF),而同一台机器上 curl 能下。
		if terr := fetchWithSystemTool(ctx, assetURL, dl); terr != nil {
			return fmt.Errorf("下载 %s: %w(curl/wget: %v)", assetName, err, terr)
		}
	}
	body, err := os.Open(dl)
	if err != nil {
		return err
	}
	defer body.Close()

	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if strings.HasSuffix(assetName, ".zip") {
		// zip:读入内存,取首个 .exe 条目写出。
		data, rerr := io.ReadAll(body)
		if rerr != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("读取 zip: %w", rerr)
		}
		zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if zerr != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("解析 zip: %w", zerr)
		}
		var wrote bool
		for _, ze := range zr.File {
			if strings.HasSuffix(strings.ToLower(ze.Name), ".exe") {
				rc, e := ze.Open()
				if e != nil {
					continue
				}
				_, e = io.Copy(f, rc)
				rc.Close()
				if e != nil {
					f.Close()
					os.Remove(tmp)
					return fmt.Errorf("解压 exe: %w", e)
				}
				wrote = true
				break
			}
		}
		if !wrote {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("zip 内未找到 .exe")
		}
	} else {
		gz, gerr := gzip.NewReader(body)
		if gerr != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("gunzip: %w", gerr)
		}
		if _, cerr := io.Copy(f, gz); cerr != nil {
			gz.Close()
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("写入二进制: %w", cerr)
		}
		gz.Close()
	}
	f.Close()
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// fetchWithResume 把 url 下到 path,断了就带 Range 接着下,最多试 6 次。
// 家用线路连 GitHub 的大文件经常半路被掐(unexpected EOF),整包重来几乎下不完。
func fetchWithResume(ctx context.Context, url, path string) error {
	os.Remove(path)
	client := &http.Client{Timeout: 10 * time.Minute}
	// 后几次改用 HTTP/1.1:有些中间盒对 HTTP/2 处理不好,表现为连接直接被关(EOF)。
	h1 := &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{
		Proxy:        http.ProxyFromEnvironment,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}}
	var lastErr error
	for attempt := 1; attempt <= 6; attempt++ {
		if attempt == 4 {
			client = h1
		}
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		var have int64
		if st, err := os.Stat(path); err == nil {
			have = st.Size()
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if have > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[speedtester] 第 %d 次连接下载地址失败: %v", attempt, err)
			continue
		}
		flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		switch {
		case resp.StatusCode == http.StatusOK:
			flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC // 服务端不认 Range,从头来
		case resp.StatusCode == http.StatusPartialContent && have > 0:
		case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && have > 0:
			resp.Body.Close()
			return nil // 已经下完了
		default:
			resp.Body.Close()
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		f, err := os.OpenFile(path, flag, 0644)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, err = io.Copy(f, resp.Body)
		resp.Body.Close()
		f.Close()
		if err == nil {
			return nil
		}
		lastErr = err
		if st, serr := os.Stat(path); serr == nil {
			log.Printf("[speedtester] 下载中断(%v),已下 %d 字节,第 %d 次续传...", err, st.Size(), attempt)
		}
	}
	return lastErr
}

// fetchWithSystemTool 用系统的 curl(没有就 wget)把 url 下到 path,带续传与重试。
func fetchWithSystemTool(ctx context.Context, url, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if bin, err := exec.LookPath("curl"); err == nil {
		log.Printf("[speedtester] 改用 curl 下载...")
		out, err := exec.CommandContext(ctx, bin, "-fsSL", "-C", "-", "--retry", "5", "--retry-delay", "3",
			"--connect-timeout", "20", "-o", path, url).CombinedOutput()
		if err == nil {
			return nil
		}
		return fmt.Errorf("curl: %v %s", err, strings.TrimSpace(string(out)))
	}
	if bin, err := exec.LookPath("wget"); err == nil {
		log.Printf("[speedtester] 改用 wget 下载...")
		out, err := exec.CommandContext(ctx, bin, "-q", "-c", "-O", path, url).CombinedOutput()
		if err == nil {
			return nil
		}
		return fmt.Errorf("wget: %v %s", err, strings.TrimSpace(string(out)))
	}
	return fmt.Errorf("系统里没有 curl / wget")
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "miaomiaowux-speedtest")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询 mihomo release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 mihomo release HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}
