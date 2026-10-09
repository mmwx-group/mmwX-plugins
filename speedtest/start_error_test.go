package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 内核秒退时要立刻失败并带出它自己的报错,不再干等 15 秒只回「启动超时」。
func TestStartMihomoSurfacesCoreError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("用 shell 脚本冒充内核")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake")
	os.WriteFile(fake, []byte("#!/bin/sh\necho 'level=info msg=\"start\"'\necho 'level=fatal msg=\"Parse config error: proxy 0: unsupport proxy type: miu\"' >&2\nexit 1\n"), 0755)
	_, err := startMihomo(fake, filepath.Join(dir, "w"), []byte("x: 1"))
	if err == nil || !strings.Contains(err.Error(), "unsupport proxy type: miu") || strings.Contains(err.Error(), "超时") {
		t.Fatalf("err = %v", err)
	}
}
