// Package logger 是 substore 子包所需的轻量日志，替代主控的 internal/logger。
// 迁入 module 后日志走标准库 slog（不再写主控的 data/logs/）。
package logger

import "log/slog"

func Info(msg string, args ...any)  { slog.Info(msg, args...) }
func Warn(msg string, args ...any)  { slog.Warn(msg, args...) }
func Error(msg string, args ...any) { slog.Error(msg, args...) }
func Debug(msg string, args ...any) { slog.Debug(msg, args...) }
