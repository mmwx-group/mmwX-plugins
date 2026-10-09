---
name: mmwx-cert
description: 在妙妙屋X里管理 TLS 证书——申请、续期、部署到 nginx / xray、排查证书导致的节点连不上。当用户说"申请证书""证书过期了""部署证书""TLS 节点连不上""SNI 填什么"时使用。
---

# 证书(妙妙屋X)

## A. 申请

1. `cert_list` 先看有没有现成的,能复用就不要重复签。
2. `cert_create`:
   - `domain`:单域名(`hk.example.com`)或泛域名(`*.example.com`)。
   - `challenge_mode`:`dns`(泛域名必须用它,要给 `dns_provider_id`)/ `standalone`(要占 80 端口)/ `webroot`。
   - `remote_server_id`:在哪台机器上签,`0` 是主控。
   - 建议 `auto_renew: true`;证书要给节点或 nginx 用的话 `auto_deploy: true`。
3. 签发要等几十秒到几分钟,返回后 `cert_list_valid` 确认它在有效列表里。

## B. 续期与部署

- `cert_renew`(`id`)立即续期。
- `cert_deploy`(`id` + `deploy_target`:`nginx` / `xray` / `both`)把证书放到目标上。续期后没自动部署的,手动跑这一步。
- `cert_set_auto_renew` / `cert_set_auto_deploy` 开关自动化。

## C. 给节点用证书时,SNI 怎么填

**SNI 必须是证书覆盖的域名**,否则客户端校验证书时握手失败,节点建得出来却永远连不上。

- 单域名证书 `hk.example.com` → SNI 只能是 `hk.example.com`。
- 泛域名证书 `*.example.com` → SNI 填它的**一级**子域名,如 `node.example.com`。`a.b.example.com` 不在覆盖范围内。
- 客户端连的是 IP 时,SNI 用的那个子域名**不需要做解析**,它只用来校验证书。
- 不要把 Reality 节点用的伪装域名(如 `www.icloud.com`)填到 TLS 节点的 SNI 里。Reality 是借别人的域名,TLS 是用自己的证书,两者不是一回事。

用主控托管的证书新建 TLS 节点时,主控会拦下 SNI 与证书对不上的情况并提示证书覆盖哪些域名;手填证书路径的入站不会被检查,要自己核对。

## D. 「TLS 节点连不上」的排查顺序

1. `node_tcping` 确认端口通。端口不通是网络或防火墙问题,不是证书。
2. `node_get` 看节点配置里的 `sni` / `servername`。
3. `server_inbound_list` 看该入站用的证书路径,对照 `cert_list` 找到是哪张、覆盖哪些域名、是否过期。
4. SNI 不在证书覆盖范围 → 改节点的 SNI;证书过期 → `cert_renew` 后 `cert_deploy`。

## 注意

- `cert_delete` 需要 `confirm: true`。正在被入站或 nginx 使用的证书删掉后,相关服务会起不来。
- 自签证书(`cert_self_signed`)客户端必须开「跳过证书验证」才能连,只用于测试或 Hysteria2 这类允许不验证的场景。
