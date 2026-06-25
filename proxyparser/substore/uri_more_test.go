package substore

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// 这些测试针对 URI producer 中被改过的 encoder, 断言依据 Sub-Store 的
// uri.js 权威实现 (backend/src/core/proxy-utils/producers/uri.js)。
// 断言聚焦 scheme 前缀、关键 query 参数名/取值、base64 负载, 不依赖 query 顺序。

func produceURI(t *testing.T, proxy Proxy) string {
	t.Helper()
	uri, err := NewURIProducer().ProduceOne(proxy)
	if err != nil {
		t.Fatalf("ProduceOne error: %v", err)
	}
	return uri
}

func mustContain(t *testing.T, uri, sub string) {
	t.Helper()
	if !strings.Contains(uri, sub) {
		t.Errorf("expected URI to contain %q\n got: %s", sub, uri)
	}
}

func mustNotContain(t *testing.T, uri, sub string) {
	t.Helper()
	if strings.Contains(uri, sub) {
		t.Errorf("expected URI to NOT contain %q\n got: %s", sub, uri)
	}
}

// TestURIVMess: ws+tls vmess。JS 输出 vmess:// + base64(JSON)。
// 重点: 配置对象不含 udp 字段; scy 归一化; ws path/host 来自 ws-opts。
func TestURIVMess(t *testing.T) {
	proxy := Proxy{
		"type":               "vmess",
		"name":               "vm node",
		"server":             "example.com",
		"port":               443,
		"uuid":               "uuid-1",
		"alterId":            0,
		"cipher":             "auto",
		"tls":                true,
		"sni":                "sni.example.com",
		"network":            "ws",
		"udp":                true,
		"client-fingerprint": "chrome",
		"alpn":               []interface{}{"h2", "http/1.1"},
		"ws-opts": map[string]interface{}{
			"path": "/ws",
			"headers": map[string]interface{}{
				"Host": "host.example.com",
			},
		},
	}
	uri := produceURI(t, proxy)
	if !strings.HasPrefix(uri, "vmess://") {
		t.Fatalf("expected vmess:// prefix, got %s", uri)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "vmess://"))
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("json decode failed: %v (%s)", err, raw)
	}
	// JS vmess 配置对象中不存在 udp 字段
	if _, ok := cfg["udp"]; ok {
		t.Errorf("vmess config must NOT contain udp field, got: %v", cfg)
	}
	if cfg["net"] != "ws" {
		t.Errorf("net expected ws, got %v", cfg["net"])
	}
	if cfg["tls"] != "tls" {
		t.Errorf("tls expected 'tls', got %v", cfg["tls"])
	}
	if cfg["sni"] != "sni.example.com" {
		t.Errorf("sni expected sni.example.com, got %v", cfg["sni"])
	}
	if cfg["scy"] != "auto" {
		t.Errorf("scy expected auto, got %v", cfg["scy"])
	}
	if cfg["path"] != "/ws" {
		t.Errorf("path expected /ws, got %v", cfg["path"])
	}
	if cfg["host"] != "host.example.com" {
		t.Errorf("host expected host.example.com, got %v", cfg["host"])
	}
	if cfg["alpn"] != "h2,http/1.1" {
		t.Errorf("alpn expected 'h2,http/1.1', got %v", cfg["alpn"])
	}
	if cfg["fp"] != "chrome" {
		t.Errorf("fp expected chrome, got %v", cfg["fp"])
	}
}

// TestURIVMessHttpUpgrade: ws + v2ray-http-upgrade → net=httpupgrade。
func TestURIVMessHttpUpgrade(t *testing.T) {
	proxy := Proxy{
		"type":    "vmess",
		"name":    "n",
		"server":  "1.2.3.4",
		"port":    80,
		"uuid":    "u",
		"network": "ws",
		"ws-opts": map[string]interface{}{
			"v2ray-http-upgrade": true,
			"path":               "/p",
		},
	}
	uri := produceURI(t, proxy)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "vmess://"))
	var cfg map[string]interface{}
	_ = json.Unmarshal(raw, &cfg)
	if cfg["net"] != "httpupgrade" {
		t.Errorf("net expected httpupgrade, got %v", cfg["net"])
	}
}

// TestURIVLESSReality: reality + grpc。JS: security=reality, pbk/sid/spx,
// type=grpc, mode=<grpc-type|gun>, serviceName, flow。
func TestURIVLESSReality(t *testing.T) {
	proxy := Proxy{
		"type":               "vless",
		"name":               "vl",
		"server":             "v.example.com",
		"port":               443,
		"uuid":               "vuuid",
		"tls":                true,
		"flow":               "xtls-rprx-vision",
		"client-fingerprint": "chrome",
		"network":            "grpc",
		"reality-opts": map[string]interface{}{
			"public-key": "PBKEY",
			"short-id":   "abcd",
			"_spider-x":  "/spx",
		},
		"grpc-opts": map[string]interface{}{
			"grpc-service-name": "mygrpc",
		},
	}
	uri := produceURI(t, proxy)
	if !strings.HasPrefix(uri, "vless://vuuid@v.example.com:443?") {
		t.Fatalf("unexpected vless prefix: %s", uri)
	}
	mustContain(t, uri, "security=reality")
	mustContain(t, uri, "pbk=PBKEY")
	mustContain(t, uri, "sid=abcd")
	mustContain(t, uri, "spx=%2Fspx") // encodeURIComponent('/spx')
	mustContain(t, uri, "type=grpc")
	mustContain(t, uri, "serviceName=mygrpc")
	mustContain(t, uri, "mode=gun") // _grpc-type 缺省回退 gun
	mustContain(t, uri, "flow=xtls-rprx-vision")
	mustContain(t, uri, "fp=chrome")
}

// TestURIVLESSWS: ws + tls, 验证 path/host/sni/alpn。
func TestURIVLESSWS(t *testing.T) {
	proxy := Proxy{
		"type":    "vless",
		"name":    "vl ws",
		"server":  "h.example.com",
		"port":    443,
		"uuid":    "u2",
		"tls":     true,
		"sni":     "sni.example.com",
		"alpn":    []interface{}{"h2"},
		"network": "ws",
		"ws-opts": map[string]interface{}{
			"path": "/path",
			"headers": map[string]interface{}{
				"Host": "ws.example.com",
			},
		},
	}
	uri := produceURI(t, proxy)
	mustContain(t, uri, "security=tls")
	mustContain(t, uri, "type=ws")
	mustContain(t, uri, "sni=sni.example.com")
	mustContain(t, uri, "alpn=h2")
	// path/host 经 query 编码 (空格无, 斜杠被编码为 %2F)
	mustContain(t, uri, "host=ws.example.com")
	mustContain(t, uri, "path=%2Fpath")
}

// TestURITrojanReality: reality + ws-opts host/path, alpn, fp, pcs。
func TestURITrojanReality(t *testing.T) {
	proxy := Proxy{
		"type":               "trojan",
		"name":               "tj",
		"server":             "t.example.com",
		"port":               443,
		"password":           "pass word",
		"sni":                "sni.t.com",
		"skip-cert-verify":   true,
		"alpn":               []interface{}{"h2", "http/1.1"},
		"client-fingerprint": "firefox",
		"tls-fingerprint":    "PCSVAL",
		"network":            "grpc",
		"reality-opts": map[string]interface{}{
			"public-key": "TPBK",
			"short-id":   "ff00",
			"_spider-x":  "/s",
		},
		"grpc-opts": map[string]interface{}{
			"grpc-service-name": "tgrpc",
			"_grpc-authority":   "auth.host",
		},
	}
	uri := produceURI(t, proxy)
	if !strings.HasPrefix(uri, "trojan://pass word@") && !strings.HasPrefix(uri, "trojan://pass%20word@") {
		// password 直接拼接 (JS 不编码 password), 故应原样含空格
		t.Fatalf("unexpected trojan prefix: %s", uri)
	}
	mustContain(t, uri, "sni=sni.t.com")
	mustContain(t, uri, "allowInsecure=1")
	mustContain(t, uri, "alpn=h2%2Chttp%2F1.1") // url query escape of 'h2,http/1.1'
	mustContain(t, uri, "fp=firefox")
	mustContain(t, uri, "pcs=PCSVAL")
	mustContain(t, uri, "security=reality")
	mustContain(t, uri, "pbk=TPBK")
	mustContain(t, uri, "sid=ff00")
	mustContain(t, uri, "type=grpc")
	mustContain(t, uri, "serviceName=tgrpc")
	mustContain(t, uri, "authority=auth.host")
	mustContain(t, uri, "mode=gun")
	// JS trojan 不输出 udp 参数
	mustNotContain(t, uri, "udp=")
}

// TestURIShadowsocks: 标准 cipher → base64(cipher:password) userinfo;
// obfs plugin; tls + sni; alpn/fp。
func TestURIShadowsocks(t *testing.T) {
	proxy := Proxy{
		"type":               "ss",
		"name":               "ss node",
		"server":             "s.example.com",
		"port":               8388,
		"cipher":             "aes-128-gcm",
		"password":           "p@ss",
		"plugin":             "obfs",
		"plugin-opts":        map[string]interface{}{"mode": "http", "host": "bing.com"},
		"udp-over-tcp":       true,
		"tfo":                true,
		"client-fingerprint": "chrome",
		"alpn":               []interface{}{"h2"},
	}
	uri := produceURI(t, proxy)
	if !strings.HasPrefix(uri, "ss://") {
		t.Fatalf("expected ss:// prefix, got %s", uri)
	}
	// userinfo = base64("aes-128-gcm:p@ss")
	wantUserinfo := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p@ss"))
	mustContain(t, uri, "ss://"+wantUserinfo+"@s.example.com:8388/")
	mustContain(t, uri, "uot=1")
	mustContain(t, uri, "tfo=1")
	mustContain(t, uri, "fp=chrome")
	mustContain(t, uri, "alpn=h2")
	// plugin obfs: encodeURIComponent("simple-obfs;obfs=http;obfs-host=bing.com")
	mustContain(t, uri, "plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com")
	// JS ss 不输出 udp 参数
	mustNotContain(t, uri, "&udp=")
	// 名称使用 encodeURIComponent (空格→%20)
	mustContain(t, uri, "#ss%20node")
}

// TestURIShadowsocks2022: 2022-blake3-* cipher → 不 base64, 用
// encodeURIComponent(cipher):encodeURIComponent(password)。
func TestURIShadowsocks2022(t *testing.T) {
	proxy := Proxy{
		"type":     "ss",
		"name":     "n",
		"server":   "s.com",
		"port":     443,
		"cipher":   "2022-blake3-aes-128-gcm",
		"password": "pw/with",
	}
	uri := produceURI(t, proxy)
	// cipher 含 '-' 不被 encodeURIComponent 转义; password 的 '/' → %2F
	mustContain(t, uri, "ss://2022-blake3-aes-128-gcm:pw%2Fwith@s.com:443")
	// 不应出现 base64 的 userinfo
	b64 := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:pw/with"))
	mustNotContain(t, uri, b64)
}

// TestURISSR: ssr:// + base64(整体)。参数名 protocolparam (非 protoparam);
// 全部标准 base64 (含 padding)。
func TestURISSR(t *testing.T) {
	proxy := Proxy{
		"type":           "ssr",
		"name":           "ssrnode",
		"server":         "r.example.com",
		"port":           1234,
		"protocol":       "auth_aes128_md5",
		"cipher":         "aes-128-cfb",
		"obfs":           "tls1.2_ticket_auth",
		"password":       "mypass",
		"obfs-param":     "obfsp",
		"protocol-param": "protop",
	}
	uri := produceURI(t, proxy)
	if !strings.HasPrefix(uri, "ssr://") {
		t.Fatalf("expected ssr:// prefix, got %s", uri)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "ssr://"))
	if err != nil {
		t.Fatalf("ssr base64 decode failed: %v", err)
	}
	s := string(decoded)
	// 主体: server:port:protocol:cipher:obfs:base64(password)/
	wantPwd := base64.StdEncoding.EncodeToString([]byte("mypass"))
	mustContain(t, s, "r.example.com:1234:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:"+wantPwd+"/")
	// remarks/obfsparam/protocolparam 均为标准 base64
	mustContain(t, s, "remarks="+base64.StdEncoding.EncodeToString([]byte("ssrnode")))
	mustContain(t, s, "obfsparam="+base64.StdEncoding.EncodeToString([]byte("obfsp")))
	mustContain(t, s, "protocolparam="+base64.StdEncoding.EncodeToString([]byte("protop")))
	// 关键: 参数名是 protocolparam, 不是 protoparam
	mustNotContain(t, s, "protoparam=")
}

// TestURIHysteria2: password/name 用 encodeURIComponent; sni/obfs/insecure/mport/fastopen。
func TestURIHysteria2(t *testing.T) {
	proxy := Proxy{
		"type":             "hysteria2",
		"name":             "hy2 node",
		"server":           "hy.example.com",
		"port":             443,
		"password":         "pa ss",
		"sni":              "sni.hy.com",
		"skip-cert-verify": true,
		"obfs":             "salamander",
		"obfs-password":    "obfspw",
		"ports":            "443-500",
		"tfo":              true,
	}
	uri := produceURI(t, proxy)
	// password encodeURIComponent: 空格 → %20
	if !strings.HasPrefix(uri, "hysteria2://pa%20ss@hy.example.com:443?") {
		t.Fatalf("unexpected hysteria2 prefix: %s", uri)
	}
	mustContain(t, uri, "insecure=1")
	mustContain(t, uri, "obfs=salamander")
	mustContain(t, uri, "obfs-password=obfspw")
	mustContain(t, uri, "sni=sni.hy.com")
	mustContain(t, uri, "mport=443-500")
	mustContain(t, uri, "fastopen=1")
	mustContain(t, uri, "#hy2%20node")
	// JS hysteria2 不输出 alpn / udp
	mustNotContain(t, uri, "alpn=")
}

// TestURIHysteria: 字段映射 up→upmbps, down→downmbps, auth-str→auth,
// ports→mport, sni→peer, obfs→obfsParam, _obfs→obfs, skip-cert-verify→insecure。
func TestURIHysteria(t *testing.T) {
	proxy := Proxy{
		"type":             "hysteria",
		"name":             "hy node",
		"server":           "h.example.com",
		"port":             443,
		"up":               "100",
		"down":             "200",
		"auth-str":         "mytoken",
		"ports":            "1000-2000",
		"sni":              "peer.example.com",
		"obfs":             "myobfsparam",
		"_obfs":            "salamander",
		"skip-cert-verify": true,
		"alpn":             []interface{}{"h3"},
	}
	uri := produceURI(t, proxy)
	if !strings.HasPrefix(uri, "hysteria://h.example.com:443?") {
		t.Fatalf("unexpected hysteria prefix: %s", uri)
	}
	mustContain(t, uri, "upmbps=100")
	mustContain(t, uri, "downmbps=200")
	mustContain(t, uri, "auth=mytoken")
	mustContain(t, uri, "mport=1000-2000")
	mustContain(t, uri, "peer=peer.example.com")
	mustContain(t, uri, "obfsParam=myobfsparam")
	mustContain(t, uri, "obfs=salamander") // 来自 _obfs
	mustContain(t, uri, "insecure=1")
	mustContain(t, uri, "alpn=h3")
	mustContain(t, uri, "#hy%20node")
}
