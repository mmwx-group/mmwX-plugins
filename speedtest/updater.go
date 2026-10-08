package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func runUpdate(job wsMsg, send func(wsMsg) error) {
	reply := func(status string, progress int, err error) {
		m := wsMsg{Type: "update_progress", JobID: job.JobID, Status: status, Progress: progress, Version: version}
		if err != nil {
			m.Error = err.Error()
		}
		_ = send(m)
	}
	if strings.TrimSpace(job.TargetVersion) == "" || strings.TrimSpace(job.DownloadURL) == "" || len(strings.TrimSpace(job.SHA256)) != 64 {
		reply("failed", 0, errors.New("更新参数不完整"))
		return
	}
	u, err := url.Parse(job.DownloadURL)
	if err != nil || (u.Hostname() != "github.com" && u.Hostname() != "objects.githubusercontent.com") || u.Scheme != "https" {
		reply("failed", 0, errors.New("拒绝非官方更新地址"))
		return
	}
	reply("downloading", 10, nil)
	target, err := updateTargetPath()
	if err != nil {
		reply("failed", 0, err)
		return
	}
	tmp := target + ".download"
	defer os.Remove(tmp)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(job.DownloadURL)
	if err != nil {
		reply("failed", 0, fmt.Errorf("下载失败: %w", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		reply("failed", 0, fmt.Errorf("下载失败: HTTP %d", resp.StatusCode))
		return
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		reply("failed", 0, fmt.Errorf("创建临时文件失败: %w", err))
		return
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 200<<20))
	closeErr := f.Close()
	if copyErr != nil {
		reply("failed", 0, fmt.Errorf("下载失败: %w", copyErr))
		return
	}
	if closeErr != nil {
		reply("failed", 0, closeErr)
		return
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), strings.TrimSpace(job.SHA256)) {
		reply("failed", 0, errors.New("更新文件 SHA256 校验失败"))
		return
	}
	reply("installing", 75, nil)
	if err := os.Chmod(tmp, 0755); err != nil {
		reply("failed", 0, err)
		return
	}
	if err := installAndRestart(tmp, target); err != nil {
		reply("failed", 0, err)
		return
	}
	reply("restarting", 95, nil)
	time.Sleep(300 * time.Millisecond)
	if err := restartInto(target); err != nil {
		reply("failed", 0, fmt.Errorf("重启失败: %w", err))
	}
}

func updateTargetPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Docker 镜像中的 /usr/local/bin 对非 root 用户不可写；更新写入持久化 /data。
	if runtime.GOOS != "windows" {
		if f, err := os.OpenFile(filepath.Join(filepath.Dir(exe), ".mmwx-write-test"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
			f.Close()
			os.Remove(f.Name())
			return exe, nil
		}
		if st, err := os.Stat("/data"); err == nil && st.IsDir() {
			return "/data/mmwx-speedtester", nil
		}
	}
	return exe, nil
}

func installAndRestart(tmp, target string) error {
	if runtime.GOOS == "windows" {
		return nil
	} // Windows 由 helper 在旧进程退出后替换。
	bak := target + ".bak"
	_ = os.Remove(bak)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, bak); err != nil {
			return fmt.Errorf("备份旧程序失败: %w", err)
		}
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Rename(bak, target)
		return fmt.Errorf("替换程序失败: %w", err)
	}
	return nil
}
