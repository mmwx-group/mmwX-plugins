package proxyparser

import (
	"testing"

	"github.com/MMWOrg/mmwX-plugins/proxyparser/substore"
)

// mieru 分享链接一路解析到 Loon 的一行(Loon 已支持 mieru,上游 Sub-Store 85948dcf)。
// 从前 Loon producer 没有 mieru 分支,这类节点在 Loon 订阅里整个消失。
func TestMieruURIToLoon(t *testing.T) {
	loon := substore.NewLoonProducer()
	for _, c := range []struct {
		uri, want string
	}{
		// 上游用例:mierus:// 默认 udp 打开
		{"mierus://user:pass@example.com?port=8443&protocol=TCP#URI",
			`URI=mieru,example.com,8443,"user","pass",udp=true`},
		// 官方客户端导出的链接:端口在 query、名字取 profile;multiplexing / handshake-mode / mtu Loon 没有,不输出
		{"mierus://r2RYIiZSxS:GuoNTOfndr@116.126.122.66?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_OFF&port=11211&profile=default&protocol=TCP",
			`default=mieru,116.126.122.66,11211,"r2RYIiZSxS","GuoNTOfndr",udp=true`},
		// 社区写法:host 带端口,udp=0 关 UDP
		{"mieru://alice:s3cret@example.com:2999?transport=TCP&udp=0#我的节点",
			`我的节点=mieru,example.com,2999,"alice","s3cret"`},
		// 官方链接的端口范围:取第一个端口
		{"mierus://a:b@1.2.3.4?port=20000-20100&profile=r&protocol=TCP",
			`r=mieru,1.2.3.4,20000,"a","b",udp=true`},
	} {
		node, err := Parse(c.uri)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", c.uri, err)
		}
		got, err := loon.ProduceOne(substore.Proxy(node), "", nil)
		if err != nil {
			t.Fatalf("%s 生成 Loon 失败: %v", c.uri, err)
		}
		if got != c.want {
			t.Fatalf("%s\n got  %s\n want %s", c.uri, got, c.want)
		}
	}

	// Loon 的 mieru 只有 TCP:UDP 传输的链接跳过
	node, err := Parse("mieru://alice:s3cret@example.com:2999?transport=UDP#udp")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := loon.ProduceOne(substore.Proxy(node), "", nil); err == nil {
		t.Fatalf("UDP 传输的 mieru 应跳过, 得到 %s", out)
	}
}
