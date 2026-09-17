package substore

import (
	"strings"
	"testing"
)

func produceSurgeSnell(t *testing.T, proxy Proxy) string {
	t.Helper()
	out, err := NewSurgeProducer().Produce([]Proxy{proxy}, "", nil)
	if err != nil {
		t.Fatalf("produce Surge Snell: %v", err)
	}
	return out.(string)
}

func TestSurgeSnellDoesNotForceOptionalParameters(t *testing.T) {
	got := produceSurgeSnell(t, Proxy{
		"name": "snell", "type": "snell", "server": "example.com",
		"port": 443, "psk": "secret", "version": 4,
	})
	if strings.Contains(got, "tfo=") {
		t.Fatalf("tfo must be omitted when absent from source: %s", got)
	}
	if strings.Contains(got, "udp-relay=") {
		t.Fatalf("udp-relay must be omitted when absent from source: %s", got)
	}
}

func TestSurgeSnellOutputsExplicitOptionalParameters(t *testing.T) {
	got := produceSurgeSnell(t, Proxy{
		"name": "snell", "type": "snell", "server": "example.com",
		"port": 443, "psk": "secret", "version": 4,
		"tfo": false, "udp": true,
	})
	if !strings.Contains(got, "tfo=false") {
		t.Fatalf("explicit tfo=false missing: %s", got)
	}
	if strings.Count(got, "tfo=false") != 1 {
		t.Fatalf("explicit tfo must be output exactly once: %s", got)
	}
	if !strings.Contains(got, "udp-relay=true") {
		t.Fatalf("explicit udp-relay=true missing: %s", got)
	}
}

// Snell v6 的传输模式必须出现在 Surge 输出里,否则客户端只能按默认的 default 跑,
// 用户在面板里选的 unshaped 静默失效(#831)。位置与条件对齐 Sub-Store 上游:
// psk 之后、ip-version 之前,且**只在 version=6 时**输出。
func TestSurgeSnellV6OutputsMode(t *testing.T) {
	got := produceSurgeSnell(t, Proxy{
		"name": "snell6", "type": "snell", "server": "example.com",
		"port": 443, "psk": "secret", "version": 6, "mode": "unshaped",
	})
	if !strings.Contains(got, ",mode=unshaped") {
		t.Fatalf("v6 的 mode 没输出: %s", got)
	}
	if i, j := strings.Index(got, "psk="), strings.Index(got, "mode="); i < 0 || j < i {
		t.Fatalf("mode 必须排在 psk 之后(对齐上游顺序): %s", got)
	}
}

// v4/v5 没有这个参数 —— 它们的 mode 在 obfs-opts 里、含义是混淆方式。
// 输出到顶层会给客户端一个它不认识的参数。
func TestSurgeSnellV4DoesNotOutputMode(t *testing.T) {
	got := produceSurgeSnell(t, Proxy{
		"name": "snell4", "type": "snell", "server": "example.com",
		"port": 443, "psk": "secret", "version": 4, "mode": "unshaped",
	})
	if strings.Contains(got, ",mode=") {
		t.Fatalf("v4 不该输出顶层 mode: %s", got)
	}
}

// 没配 mode 的 v6 节点不该凭空多出一个参数。
func TestSurgeSnellV6WithoutModeStaysClean(t *testing.T) {
	got := produceSurgeSnell(t, Proxy{
		"name": "snell6", "type": "snell", "server": "example.com",
		"port": 443, "psk": "secret", "version": 6,
	})
	if strings.Contains(got, ",mode=") {
		t.Fatalf("未配置 mode 时不该输出: %s", got)
	}
}
