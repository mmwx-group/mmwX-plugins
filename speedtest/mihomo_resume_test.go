package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
