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
