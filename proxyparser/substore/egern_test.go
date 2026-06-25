package substore

import (
	"strings"
	"testing"
)

func produceEgern(t *testing.T, p Proxy) string {
	t.Helper()
	out, err := NewEgernProducer().Produce([]Proxy{p}, "", nil)
	if err != nil {
		t.Fatalf("produce err: %v", err)
	}
	return out.(string)
}

func TestEgernWireGuard(t *testing.T) {
	got := produceEgern(t, Proxy{
		"type": "wireguard", "name": "wg1",
		"ip": "10.0.0.2", "ip-cidr": 24, "ipv6": "fd00::2",
		"private-key": "PRIV", "dns": "1.1.1.1, 8.8.8.8", "mtu": 1420,
		"peers": []interface{}{map[string]interface{}{
			"server": "1.2.3.4", "port": 51820,
			"public-key": "PUB", "pre-shared-key": "PSK", "reserved": "1 / 2 / 3",
		}},
	})
	for _, want := range []string{`"wireguard"`, `"local_ipv4":"10.0.0.2/24"`, `"local_ipv6":"fd00::2/128"`,
		`"private_key":"PRIV"`, `"peer_public_key":"PUB"`, `"preshared_key":"PSK"`,
		`"reserved":["1","2","3"]`, `"dns_servers":["1.1.1.1","8.8.8.8"]`, `"mtu":1420`} {
		if !strings.Contains(got, want) {
			t.Errorf("wireguard missing %s in:\n%s", want, got)
		}
	}
}

func TestEgernSnell(t *testing.T) {
	got := produceEgern(t, Proxy{
		"type": "snell", "name": "snell1", "server": "1.2.3.4", "port": 443,
		"psk": "mypsk", "version": 4, "udp": true,
		"obfs-opts": map[string]interface{}{"mode": "http", "host": "h.com"},
	})
	for _, want := range []string{`"snell"`, `"psk":"mypsk"`, `"version":4`, `"udp_relay":true`, `"obfs":"http"`, `"obfs_host":"h.com"`} {
		if !strings.Contains(got, want) {
			t.Errorf("snell missing %s in:\n%s", want, got)
		}
	}
	// snell v2 不应有 udp_relay
	v2 := produceEgern(t, Proxy{"type": "snell", "name": "s2", "server": "x", "port": 1, "psk": "p", "version": 2, "udp": true})
	if strings.Contains(v2, "udp_relay") {
		t.Errorf("snell v2 should not have udp_relay:\n%s", v2)
	}
	// 非法 version 应被过滤
	bad := produceEgern(t, Proxy{"type": "snell", "name": "s3", "server": "x", "port": 1, "psk": "p", "version": 9})
	if strings.Contains(bad, "s3") {
		t.Errorf("snell invalid version should be filtered:\n%s", bad)
	}
}

func TestEgernSSH(t *testing.T) {
	got := produceEgern(t, Proxy{
		"type": "ssh", "name": "ssh1", "server": "1.2.3.4", "port": 22,
		"username": "root", "password": "pw", "private-key": "KEY", "host-key": []interface{}{"hk1"},
	})
	for _, want := range []string{`"ssh"`, `"username":"root"`, `"password":"pw"`, `"private_key":"KEY"`, `"host_keys":["hk1"]`} {
		if !strings.Contains(got, want) {
			t.Errorf("ssh missing %s in:\n%s", want, got)
		}
	}
}

func TestEgernAnyTLS(t *testing.T) {
	got := produceEgern(t, Proxy{
		"type": "anytls", "name": "at1", "server": "1.2.3.4", "port": 443,
		"password": "pw", "sni": "a.com", "skip-cert-verify": true,
		"reality-opts": map[string]interface{}{"public-key": "PK", "short-id": "SID"},
	})
	for _, want := range []string{`"anytls"`, `"password":"pw"`, `"sni":"a.com"`, `"skip_tls_verify":true`, `"reality":{`, `"public_key":"PK"`, `"short_id":"SID"`} {
		if !strings.Contains(got, want) {
			t.Errorf("anytls missing %s in:\n%s", want, got)
		}
	}
	// network 非 tcp 应被过滤
	bad := produceEgern(t, Proxy{"type": "anytls", "name": "atbad", "server": "x", "port": 1, "network": "ws"})
	if strings.Contains(bad, "atbad") {
		t.Errorf("anytls non-tcp should be filtered:\n%s", bad)
	}
}

func TestEgernGrpc(t *testing.T) {
	got := produceEgern(t, Proxy{
		"type": "vless", "name": "v1", "server": "1.2.3.4", "port": 443, "uuid": "uid",
		"network": "grpc", "tls": true, "sni": "g.com", "skip-cert-verify": true,
		"grpc-opts": map[string]interface{}{"grpc-service-name": "gsn"},
	})
	for _, want := range []string{`"vless"`, `"grpc":{`, `"service_name":"gsn"`, `"sni":"g.com"`, `"skip_tls_verify":true`} {
		if !strings.Contains(got, want) {
			t.Errorf("vless grpc missing %s in:\n%s", want, got)
		}
	}
	// multi 模式 gRPC 应被过滤
	bad := produceEgern(t, Proxy{"type": "vmess", "name": "gm", "server": "x", "port": 1, "uuid": "u",
		"network": "grpc", "grpc-opts": map[string]interface{}{"_grpc-type": "multi"}})
	if strings.Contains(bad, "gm") {
		t.Errorf("multi grpc should be filtered:\n%s", bad)
	}
}
