// Package speedtest 在主控本机用 mihomo 内核对节点测速(PRO 功能 speed_test 的 Phase 1)。
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
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
		log.Printf("[warn] 带 Miu 的 mihomo 下载失败,改用官方内核(Miu 节点测不了): %v", err)
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("下载 %s: %w", assetName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 %s HTTP %d", assetName, resp.StatusCode)
	}

	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if strings.HasSuffix(assetName, ".zip") {
		// zip:读入内存,取首个 .exe 条目写出。
		data, rerr := io.ReadAll(resp.Body)
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
		gz, gerr := gzip.NewReader(resp.Body)
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
