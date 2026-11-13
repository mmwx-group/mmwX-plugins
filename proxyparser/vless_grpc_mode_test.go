package proxyparser

import "testing"

// VLESS 分享链接的 gRPC mode / authority 记进 grpc-opts 的内部字段(Surge / Egern 用,clash 系输出前删掉)
func TestParseVlessGRPCModeAuthority(t *testing.T) {
	node, err := parseVlessURL("vless://u1@1.2.3.4:443?type=grpc&serviceName=svc&mode=multi&authority=a.example.com&security=tls&sni=a.example.com#g")
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := node["grpc-opts"].(map[string]any)
	if opts["grpc-service-name"] != "svc" || opts["_grpc-type"] != "multi" || opts["_grpc-authority"] != "a.example.com" {
		t.Fatalf("grpc-opts = %v", opts)
	}
	plain, err := parseVlessURL("vless://u1@1.2.3.4:443?type=grpc&serviceName=svc&security=tls#g")
	if err != nil {
		t.Fatal(err)
	}
	if o, _ := plain["grpc-opts"].(map[string]any); o["_grpc-type"] != nil || o["_grpc-authority"] != nil {
		t.Fatalf("没带 mode / authority 时不该有内部字段: %v", o)
	}
}
