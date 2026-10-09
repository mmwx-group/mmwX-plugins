package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// 下到的内核在本机跑不起来(-v 崩掉、没有输出)时:保留原有内核、记下这个包、不再重复下载;
// 能跑的才替换。
func TestMiuCoreIsVerifiedBeforeReplacing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("用 shell 脚本冒充内核")
	}
	broken := []byte("#!/bin/sh\nkill -SEGV $$\n")
	oldRev := []byte("#!/bin/sh\necho 'Mihomo Meta miu2-abc1234 linux amd64'\n")
	good := []byte("#!/bin/sh\necho 'Mihomo Meta miu2-r2-abc1234 linux amd64'\n")
	payload := broken
	downloads := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dl/") {
			downloads++
			w.Write(gz(payload))
			return
		}
		name := "mihomo-miu-" + runtime.GOOS + "-" + runtime.GOARCH + ".gz"
		tag := strings.TrimPrefix(r.URL.Query().Get("v"), "")
		json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": miuCoreTagPrefix + "t" + tag,
			"assets":   []map[string]any{{"name": name, "browser_download_url": srv.URL + "/dl/" + tag + "/" + name}},
		}})
	}))
	defer srv.Close()
	oldURL := miuReleasesURL
	defer func() { miuReleasesURL = oldURL }()

	dir := t.TempDir()
	local := filepath.Join(dir, "mihomo")
	official := []byte("#!/bin/sh\necho 'Mihomo Meta v1.19.30 linux amd64'\n")
	if err := os.WriteFile(local, official, 0755); err != nil {
		t.Fatal(err)
	}
	if !mihomoRuns(local) {
		t.Fatal("正常的内核应判为能跑")
	}

	// 1. 坏包:拒绝,原内核原样保留
	miuReleasesURL = srv.URL + "/releases?v=1"
	if err := downloadMiuMihomo(context.Background(), local); err == nil {
		t.Fatal("跑不起来的包应被拒绝")
	}
	if got, _ := os.ReadFile(local); !bytes.Equal(got, official) {
		t.Fatal("原有内核被动了")
	}
	if _, err := os.Stat(filepath.Join(dir, "miu-new-mihomo")); err == nil {
		t.Fatal("候选文件没清掉")
	}
	if b, _ := os.ReadFile(miuRejectedFile(local)); !strings.Contains(string(b), "/dl/1/") {
		t.Fatalf("没记下被拒绝的包: %q", b)
	}
	// 2. 同一个包不再下载
	if err := downloadMiuMihomo(context.Background(), local); err == nil || downloads != 1 {
		t.Fatalf("同一个包不该再下一遍: err=%v downloads=%d", err, downloads)
	}
	// 3. 能跑但修订不够的包(最新的还是旧内核):同样拒绝并记下,原内核保留
	payload = oldRev
	miuReleasesURL = srv.URL + "/releases?v=3"
	if err := downloadMiuMihomo(context.Background(), local); err == nil || !strings.Contains(err.Error(), "修订") {
		t.Fatalf("修订不够的包应被拒绝并说明原因: %v", err)
	}
	if got, _ := os.ReadFile(local); !bytes.Equal(got, official) {
		t.Fatal("原有内核被动了")
	}
	if b, _ := os.ReadFile(miuRejectedFile(local)); !strings.Contains(string(b), "/dl/3/") {
		t.Fatalf("没记下修订不够的包: %q", b)
	}
	// 4. 发了新包(地址变了)且能跑、修订够:替换,清掉拒绝记录
	payload = good
	miuReleasesURL = srv.URL + "/releases?v=2"
	if err := downloadMiuMihomo(context.Background(), local); err != nil {
		t.Fatalf("能跑的新包应被接受: %v", err)
	}
	if !mihomoSupportsMiu(local) {
		t.Fatal("内核没有换成带 Miu 的")
	}
	if _, err := os.Stat(miuRejectedFile(local)); err == nil {
		t.Fatal("拒绝记录没清掉")
	}
}

func TestMihomoRunsRejectsCrashingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("用 shell 脚本冒充内核")
	}
	dir := t.TempDir()
	crash := filepath.Join(dir, "crash")
	os.WriteFile(crash, []byte("#!/bin/sh\nkill -SEGV $$\n"), 0755)
	silent := filepath.Join(dir, "silent")
	os.WriteFile(silent, []byte("#!/bin/sh\nexit 0\n"), 0755)
	if mihomoRuns(crash) || mihomoRuns(silent) || mihomoRuns(filepath.Join(dir, "missing")) {
		t.Fatal("崩掉 / 没输出 / 不存在的内核都不该判为能跑")
	}
	// 版本号解析不出来时 snell 检查会放行 —— 这正是崩掉的内核以前被当成就绪的原因
	if !mihomoSupportsSnell(crash) {
		t.Skip("snell 检查的保守放行行为变了")
	}
}
