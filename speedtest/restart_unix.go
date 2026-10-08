//go:build !windows

package main

import (
	"os"
	"syscall"
)

func restartInto(target string) error {
	return syscall.Exec(target, append([]string{target}, os.Args[1:]...), os.Environ())
}
