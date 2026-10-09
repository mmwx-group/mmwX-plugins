package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPickMiuAsset(t *testing.T) {
	var rels []ghRelease
	if err := json.Unmarshal([]byte(`[
	  {"tag_name":"speedtest-v0.1.6","assets":[{"name":"mmwx-speedtester-linux-amd64","browser_download_url":"u0"}]},
	  {"tag_name":"mihomo-miu-v2-bbbbbbb","assets":[
	    {"name":"mihomo-miu-linux-amd64.gz","browser_download_url":"new-amd64"},
	    {"name":"mihomo-miu-windows-amd64.gz","browser_download_url":"new-win"}]},
	  {"tag_name":"mihomo-miu-v2-aaaaaaa","assets":[
	    {"name":"mihomo-miu-linux-amd64.gz","browser_download_url":"old-amd64"},
	    {"name":"mihomo-miu-linux-arm64.gz","browser_download_url":"old-arm64"}]},
	  {"tag_name":"mihomo-miu-214dbe5","assets":[
	    {"name":"mihomo-miu-linux-amd64.gz","browser_download_url":"v1-amd64"},
	    {"name":"mihomo-miu-darwin-arm64.gz","browser_download_url":"v1-darwin"}]}
	]`), &rels); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ goos, goarch, want string }{
		{"linux", "amd64", "new-amd64"},
		{"windows", "amd64", "new-win"},
		{"linux", "arm64", "old-arm64"}, // 最新一版没有这个平台,退到上一版
		{"darwin", "arm64", ""},         // 只有第一版的包有这个平台:第一版与现在的节点不通,不能选
	} {
		if got, _ := pickMiuAsset(rels, c.goos, c.goarch); got != c.want {
			t.Errorf("%s/%s: got %q, want %q", c.goos, c.goarch, got, c.want)
		}
	}
}

func TestMihomoSupportsMiu(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("用 shell 脚本冒充内核")
	}
	dir := t.TempDir()
	fake := func(name, out string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho '"+out+"'\n"), 0755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	official := fake("official", "Mihomo Meta v1.19.30 linux amd64 with go1.26")
	miuV1 := fake("miu-v1", "Mihomo Meta miu-214dbe5 linux amd64 with go1.26")
	miu := fake("miu", "Mihomo Meta miu2-4309534 linux amd64 with go1.27")
	if mihomoSupportsMiu(official) {
		t.Error("官方内核不该被认成带 Miu")
	}
	if mihomoSupportsMiu(miuV1) {
		t.Error("第一版 Miu 的内核不该被认成可用:它与第二版节点不通,要换掉")
	}
	if !mihomoSupportsMiu(miu) {
		t.Error("带 Miu 的内核没认出来")
	}
	// 版本号里解析不出 X.Y.Z 时 snell 检查保守放行,带 Miu 的包不能被它挡掉
	if !mihomoSupportsSnell(miu) {
		t.Error("带 Miu 的内核被 snell 版本检查挡掉了")
	}
}

// 端到端:MIU_E2E_BIN 指向带 Miu 的 mihomo,MIU_E2E_NODE 是节点的 clash 配置 JSON。
func TestMiuNodeEndToEnd(t *testing.T) {
	bin, node := os.Getenv("MIU_E2E_BIN"), strings.TrimSpace(os.Getenv("MIU_E2E_NODE"))
	if bin == "" || node == "" {
		t.Skip("MIU_E2E_BIN / MIU_E2E_NODE not set")
	}
	res, err := RunNodeTest(context.Background(), bin, node, Options{TestDuration: 5 * time.Second})
	if err != nil {
		t.Fatalf("RunNodeTest: %v", err)
	}
	t.Logf("result: %+v", res)
}
