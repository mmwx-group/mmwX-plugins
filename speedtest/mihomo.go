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
	"sync/atomic"
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

// miuCoreRepo:带 Miu 协议出站的 mihomo(源码:MiuProtocol/mihomo 的 Alpha 分支 = 上游 mihomo + Miu 出站)
// 的预编译包发在这个仓库,tag 形如 mihomo-miu-v2-<版本>,资源名 mihomo-miu-<os>-<arch>.gz。
// 官方 mihomo 不认 type: miu,测 Miu 节点必须用这份。
//
// Miu 的线上格式换过一次(第二版:通道池 + 原样转发),两版互不兼容,节点现在都是第二版。
// tag 前缀与版本标记都带上「2」:第一版的包(tag mihomo-miu-<提交>、版本号 miu-<提交>)不再被选中,
// 本地缓存着第一版内核的测速端会自动换成第二版。
const (
	miuCoreRepo      = "mmwx-group/mmwX-plugins"
	miuCoreTagPrefix = "mihomo-miu-v2-"
	miuCoreMarker    = "miu2-"
	// miuCoreMinRev 要求的内核修订号。我们的内核除了 Miu 还会补官方 mihomo 没有的能力,每补一项修订号加一,
	// 版本号写成 miu2-r<修订>-<提交>(没有 r 段的是修订 1)。本地缓存的内核修订不够就去下新包;
	// 下不到时照旧先用着旧的(只是新补的那项测不了)。
	//   2 = AnyTLS 支持 REALITY(reality-opts;官方 mihomo 不支持这个组合)
	miuCoreMinRev = 2
)

var miuCoreRevRe = regexp.MustCompile(`miu2-r(\d+)-`)

// miuCoreRev 从 `-v` 的输出里取内核修订号:不是带 Miu 第二版的内核返回 0,没有 r 段的返回 1。
func miuCoreRev(versionOutput string) int {
	out := strings.ToLower(versionOutput)
	if !strings.Contains(out, miuCoreMarker) {
		return 0
	}
	if m := miuCoreRevRe.FindStringSubmatch(out); m != nil {
		if rev, err := strconv.Atoi(m[1]); err == nil {
			return rev
		}
	}
	return 1
}

// mihomoSupportsMiu 看 `<bin> -v` 的输出:是带第二版 Miu 的内核(我们的构建把版本号写成 miu2-…),
// 并且修订号不低于 miuCoreMinRev。
func mihomoSupportsMiu(bin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	return miuCoreRev(string(out)) >= miuCoreMinRev
}

// mihomoRuns 真的执行一次 `<bin> -v`:正常退出且有输出才算能用。
//
// 只看文件在不在是不够的:Go 1.27.0 编的那批 mihomo-miu-v2 包在部分机器上一加载就段错误
// (用户的路由器,内核 6.18-rc6),`-v` 没有任何输出。而版本号解析不出来时 mihomoSupportsSnell
// 会保守放行 —— 于是崩掉的内核被判成「就绪」,之后每个测速任务都失败。
func mihomoRuns(bin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// miuRejectedFile 记下「下到了但在本机跑不起来」的那个包的下载地址。同一个包不再反复下
// (二十多 MB,每 10 分钟一次);发了新包地址变了才会再试。
func miuRejectedFile(local string) string { return local + ".miu-rejected" }

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

	// 内核还没就绪、EnsureMihomo 正在定位 / 下载它。测速任务据此立刻回「内核还在准备」,
	// 而不是排在同一把锁后面干等 —— 那样主控只会显示「超时」,看不出原因。
	mihomoPreparing atomic.Bool
	dlName          atomic.Value // string:正在下的资源名,没在下时为 ""
	dlGot, dlTotal  atomic.Int64 // 已下 / 总字节(总数未知时为 0)
)

// mihomoBusyReason 内核正在准备时返回给主控看的原因;已就绪或没在准备时返回 ""。
func mihomoBusyReason() string {
	if !mihomoPreparing.Load() {
		return ""
	}
	name, _ := dlName.Load().(string)
	if name == "" {
		return "mihomo 内核还在准备,请稍后再测"
	}
	return "mihomo 内核还在下载(" + dlProgress() + "),下完再测"
}

// dlProgress 形如 "5.2 / 21.6 MB,24%";总大小未知时只有已下的部分。
func dlProgress() string {
	got, total := dlGot.Load(), dlTotal.Load()
	const mb = 1 << 20
	if total <= 0 {
		return fmt.Sprintf("已下 %.1f MB", float64(got)/mb)
	}
	return fmt.Sprintf("%.1f / %.1f MB,%d%%", float64(got)/mb, float64(total)/mb, got*100/total)
}

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
	mihomoPreparing.Store(true)
	defer mihomoPreparing.Store(false)
	// 每个候选都要求版本支持 snell(>= minMihomoVersion),否则跳过、最终重新下载最新。
	if p := os.Getenv("MIHOMO_BIN"); p != "" && fileExists(p) && mihomoSupportsSnell(p) {
		cachedPath = p
		return p, nil
	}
	local := filepath.Join(mihomoCacheDir, mihomoBinName())
	// 本地缓存的内核跑不起来(下坏了,或换了机器 / 系统后不兼容)就当它不存在,后面重新准备。
	if fileExists(local) && !mihomoRuns(local) {
		log.Printf("[warn] %s 在本机无法执行,弃用并重新准备内核", local)
		_ = os.Remove(local)
	}
	localOK := fileExists(local) && mihomoSupportsSnell(local)
	if localOK && mihomoSupportsMiu(local) {
		cachedPath = local
		return local, nil
	}
	pathBin, perr := exec.LookPath("mihomo")
	pathOK := perr == nil && mihomoRuns(pathBin) && mihomoSupportsSnell(pathBin)
	if pathOK && mihomoSupportsMiu(pathBin) {
		cachedPath = pathBin
		return pathBin, nil
	}
	if err := downloadMiuMihomo(ctx, local); err == nil {
		cachedPath = local
		return local, nil
	} else {
		log.Printf("[warn] 带 Miu 的 mihomo 没能换上,先用官方内核(Miu 节点暂时测不了),后台每 10 分钟重试: %v", err)
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
	if !mihomoRuns(local) {
		_ = os.Remove(local)
		return "", fmt.Errorf("下载到的 mihomo 在本机无法执行(%s/%s),请手动放一个能用的内核到 %s 或用 MIHOMO_BIN 指定", runtime.GOOS, runtime.GOARCH, local)
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

// pickMiuAsset 在一批 release 里找最新的 mihomo-miu-v2-* 里匹配平台的资源(列表接口按时间倒序)。
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
// miuReleasesURL 带 Miu 的内核包所在的 release 列表(变量是为了测试里能指到本地)。
var miuReleasesURL = "https://api.github.com/repos/" + miuCoreRepo + "/releases?per_page=30"

func downloadMiuMihomo(ctx context.Context, dst string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, miuReleasesURL, nil)
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
	if prev, _ := os.ReadFile(miuRejectedFile(dst)); strings.TrimSpace(string(prev)) == assetURL {
		return fmt.Errorf("%s 上次下到后不能用(跑不起来或修订不够),等发新包再试", assetName)
	}
	// 先下到旁边,真的跑一次确认是带 Miu 的内核再替换:直接覆盖的话,包在本机跑不起来
	// (见 mihomoRuns)就连原来能用的内核也一起没了。
	cand := filepath.Join(filepath.Dir(dst), "miu-new-"+filepath.Base(dst))
	defer os.Remove(cand)
	if err := downloadMihomoAsset(ctx, assetURL, assetName, cand); err != nil {
		return err
	}
	if !mihomoRuns(cand) {
		_ = os.WriteFile(miuRejectedFile(dst), []byte(assetURL+"\n"), 0644)
		return fmt.Errorf("%s 在本机无法执行(下载完整,但运行 -v 失败),保留原有内核", assetName)
	}
	// 能跑但不够新(最新的包还是旧修订:新内核包还没发出来),同样记下,等发新包再试。
	if !mihomoSupportsMiu(cand) {
		_ = os.WriteFile(miuRejectedFile(dst), []byte(assetURL+"\n"), 0644)
		return fmt.Errorf("%s 不是带 Miu 的内核或修订号低于 r%d,保留原有内核", assetName, miuCoreMinRev)
	}
	_ = os.Remove(miuRejectedFile(dst))
	return os.Rename(cand, dst)
}

// downloadMihomoAsset 下载一个 release 资源并解到 dst:.zip 取其中的 .exe,其余按 .gz 单二进制。
func downloadMihomoAsset(ctx context.Context, assetURL, assetName, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	log.Printf("[speedtester] 下载内核 %s ...", assetName)
	dl := dst + ".dl"
	defer os.Remove(dl)
	dlGot.Store(0)
	dlTotal.Store(0)
	dlName.Store(assetName)
	defer dlName.Store("")
	stopProgress := make(chan struct{})
	defer close(stopProgress)
	go func() { // 每 15 秒报一次进度:国内线路下这二十多 MB 常要几分钟,没有输出看着像卡死
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopProgress:
				return
			case <-t.C:
				log.Printf("[speedtester] 内核下载中: %s", dlProgress())
			}
		}
	}()
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
		dlGot.Store(have)
		if resp.StatusCode == http.StatusOK {
			dlGot.Store(0)
			have = 0
		}
		if resp.ContentLength > 0 {
			dlTotal.Store(have + resp.ContentLength)
		}
		_, err = io.Copy(f, io.TeeReader(resp.Body, countingWriter{&dlGot}))
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

// countingWriter 把写入的字节数累加到 n,给下载进度用。
type countingWriter struct{ n *atomic.Int64 }

func (c countingWriter) Write(p []byte) (int, error) {
	c.n.Add(int64(len(p)))
	return len(p), nil
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
