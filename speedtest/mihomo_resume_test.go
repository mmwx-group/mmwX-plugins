package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 服务端每次只吐一部分就掐连接:要能靠 Range 续传拼出完整文件并解出内核。
func TestDownloadAssetResumesAfterCut(t *testing.T) {
	want := bytes.Repeat([]byte("miu-core-payload-"), 40000)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(want)
	w.Close()
	data := gz.Bytes()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		calls++
		var start int
		if rg := r.Header.Get("Range"); rg != "" {
			_, _ = fmtSscanf(rg, &start)
			rw.Header().Set("Content-Range", "bytes")
			rw.WriteHeader(http.StatusPartialContent)
		}
		end := start + len(data)/3
		if end >= len(data) || calls >= 4 {
			rw.Write(data[start:])
			return
		}
		rw.Write(data[start:end])
		rw.(http.Flusher).Flush()
		hj, _ := rw.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "bin", "mihomo")
	if err := downloadMihomoAsset(context.Background(), srv.URL, "mihomo-miu-linux-amd64.gz", dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatalf("content mismatch: %d vs %d", len(got), len(want))
	}
	if calls < 2 {
		t.Fatalf("expected resume, calls=%d", calls)
	}
}

func fmtSscanf(rg string, start *int) (int, error) {
	n := 0
	for _, c := range rg[len("bytes="):] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	*start = n
	return 1, nil
}

// 内核没就绪时到达的任务要立刻拿到原因(带下载进度),不能排在锁后面等到主控超时。
func TestMihomoBusyReason(t *testing.T) {
	defer func() { mihomoPreparing.Store(false); dlName.Store(""); dlGot.Store(0); dlTotal.Store(0) }()
	mihomoPreparing.Store(false)
	if r := mihomoBusyReason(); r != "" {
		t.Fatalf("没在准备时不该有原因: %q", r)
	}
	mihomoPreparing.Store(true)
	dlName.Store("")
	if r := mihomoBusyReason(); !strings.Contains(r, "还在准备") {
		t.Fatalf("准备中(没在下载): %q", r)
	}
	dlName.Store("mihomo-miu-linux-amd64.gz")
	dlGot.Store(5 << 20)
	dlTotal.Store(20 << 20)
	if r := mihomoBusyReason(); !strings.Contains(r, "5.0 / 20.0 MB") || !strings.Contains(r, "25%") {
		t.Fatalf("下载中: %q", r)
	}
	dlTotal.Store(0)
	if r := mihomoBusyReason(); !strings.Contains(r, "已下 5.0 MB") {
		t.Fatalf("总大小未知: %q", r)
	}
}

// fetchWithResume 边下边记进度:下完时已下 = 总大小 = 文件大小。
func TestFetchWithResumeCountsProgress(t *testing.T) {
	body := bytes.Repeat([]byte("k"), 300<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "k.gz", time.Time{}, bytes.NewReader(body))
	}))
	defer srv.Close()
	dst := filepath.Join(t.TempDir(), "k.dl")
	if err := fetchWithResume(context.Background(), srv.URL, dst); err != nil {
		t.Fatal(err)
	}
	if got, total := dlGot.Load(), dlTotal.Load(); got != int64(len(body)) || total != int64(len(body)) {
		t.Fatalf("got=%d total=%d, want %d", got, total, len(body))
	}
}
