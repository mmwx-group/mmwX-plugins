package substore

// Snell + ShadowTLS 有两种写法:
//   - mihomo / Shadowrocket 原生:obfs-opts { mode: shadow-tls, host, password, version }(妙妙屋X 生成的节点就是这种)
//   - 从 Sub-Store 移植的各 producer 认的:plugin: shadow-tls + plugin-opts { host, password, version }
//     (或 Surge 风格的 shadow-tls-password / shadow-tls-sni / shadow-tls-version 字段)
// 不换过来的话,Surge 会写成 obfs=shadow-tls(Surge 不认),sing-box 直接把 ShadowTLS 丢掉、节点连不上。

// isSnellShadowTLS 这个 Snell 节点有没有套 ShadowTLS(三种写法任一)。
func isSnellShadowTLS(proxy Proxy) bool {
	if GetString(proxy, "type") != "snell" {
		return false
	}
	if obfs := GetMap(proxy, "obfs-opts"); obfs != nil && GetString(obfs, "mode") == "shadow-tls" {
		return true
	}
	return GetString(proxy, "plugin") == "shadow-tls" || IsPresent(proxy, "shadow-tls-password")
}

// snellShadowTLSAsPlugin 把 obfs-opts 写法换成 plugin 写法,返回副本;不是这种节点原样返回。
func snellShadowTLSAsPlugin(proxy Proxy) Proxy {
	if GetString(proxy, "type") != "snell" {
		return proxy
	}
	obfs := GetMap(proxy, "obfs-opts")
	if obfs == nil || GetString(obfs, "mode") != "shadow-tls" {
		return proxy
	}
	out := make(Proxy, len(proxy)+1)
	for k, v := range proxy {
		out[k] = v
	}
	opts := map[string]interface{}{
		"host":     obfs["host"],
		"password": obfs["password"],
		"version":  obfs["version"],
	}
	if alpn, ok := obfs["alpn"]; ok && alpn != nil && alpn != "" {
		opts["alpn"] = alpn
	}
	out["plugin"] = "shadow-tls"
	out["plugin-opts"] = opts
	delete(out, "obfs-opts")
	return out
}
