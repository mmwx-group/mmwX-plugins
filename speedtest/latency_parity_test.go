package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// 「只测延迟」和「测速时顺带测延迟」必须用同一套口径。
//
// 用户实报(复发工单):组合测速报出来的延迟明显高于只测延迟。根因是两条路径各测各的 ——
// LatencyOnly 走 Cloudflare 端点 + 多采样取最快 2 个(去掉冷启动),而组合路径走的是
// gstatic 端点 + **单次采样**(含 TLS 握手与 mihomo 冷启动)。两个数字在同一个界面上
// 并排显示,用户只会认为其中一个是错的。
//
// 上一轮修复声称"已统一为多采样口径",实际只改了 LatencyOnly 那一支 —— 所以这次用
// **语法树**钉死:Run 里对延迟的调用只能有一种,再有人加第二种测法就会红。
func TestBothPathsUseSameLatencyMeasurement(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "runner.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 runner.go: %v", err)
	}
	called := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if strings.HasPrefix(ident.Name, "measureLatency") {
			called[ident.Name]++
		}
		return true
	})
	if len(called) == 0 {
		t.Fatal("runner.go 里找不到任何延迟测量调用")
	}
	if len(called) > 1 {
		t.Fatalf("存在多套延迟口径 %v —— 两条路径必须用同一个测法,"+
			"否则「只测延迟」与「测速带延迟」会报出不同的数", called)
	}
	for name := range called {
		if name != "measureLatencyCloudflare" {
			t.Errorf("延迟应统一走 measureLatencyCloudflare(多采样、去冷启动),实际用了 %s", name)
		}
	}
}

// 采样参数本身要有意义:单次采样等于没去掉冷启动。
func TestLatencySamplesDropColdStart(t *testing.T) {
	if cfLatencySamples < 2 {
		t.Fatalf("cfLatencySamples = %d,至少要 2 次才谈得上去掉首包冷启动", cfLatencySamples)
	}
}
