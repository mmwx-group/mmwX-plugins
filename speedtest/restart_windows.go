//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func restartInto(target string) error {
	tmp := target + ".download"
	args := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		args = append(args, "'"+strings.ReplaceAll(a, "'", "''")+"'")
	}
	cmd := fmt.Sprintf("Wait-Process -Id %d; Move-Item -Force '%s' '%s'; Start-Process '%s' -ArgumentList @(%s)", os.Getpid(), tmp, target, target, strings.Join(args, ","))
	if err := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", cmd).Start(); err != nil {
		return err
	}
	os.Exit(0)
	return strconv.ErrSyntax
}
