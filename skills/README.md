# 妙妙屋X Claude Agent Skills

一组 Claude Agent Skills,配合妙妙屋X主控内置的 MCP server 使用,让 agent(如 OpenClaw)用自然语言完成常见运维。

## 前置:接好 MCP

1. 在妙妙屋X **个人设置 → API 令牌** 生成一枚令牌(权限与你的账号一致)。
2. 在你的 MCP 客户端里把妙妙屋X 配成一个远程(streamable-HTTP)MCP server,鉴权用 `Authorization: Bearer <令牌>`。下面给出两种常见客户端的写法。
3. 把本目录的各技能(`mmwx-*/`)放入客户端的 skills 目录(或 agent 工作区)。

### OpenClaw(`openclaw.json`)
```json
{
  "mcp": {
    "servers": {
      "miaomiaowux": {
        "url": "https://你的主控/mcp",
        "transport": "streamable-http",
        "headers": { "Authorization": "Bearer <你的 API 令牌>" }
      }
    }
  }
}
```

### Hermes Agent(`~/.hermes/config.yaml`,顶层加 `mcp_servers`)
```yaml
mcp_servers:
  miaomiaowux:
    url: "https://你的主控/mcp"
    headers:
      Authorization: "Bearer <你的 API 令牌>"
    connect_timeout: 15
    timeout: 600          # 关键:安装 xray/nginx 等工具会阻塞数分钟,超时给大点
    # 可选:只放开想让 agent 用的工具(收紧爆炸半径)
    # tools:
    #   include: [server_list, user_list, package_list, traffic_summary, node_list]
```
加完**重启 hermes**(MCP 在启动时连接);成功后日志会出现
`MCP server 'miaomiaowux' (HTTP): registered N tool(s)`(N 随主控版本而变,目前是 138)。已在 Telegram 渠道实测对话可调用。

> 其它兼容 MCP 的客户端(Claude Code、Cursor 等)同理:填 `/mcp` 的 URL + Bearer 头即可。

## 技能一览

| 技能 | 用来做什么 |
|---|---|
| `mmwx-add-server` | 接入一台新服务器、装 xray / nginx、建第一个入站 |
| `mmwx-onboard-user` | 开用户、分配套餐、发订阅 |
| `mmwx-forward` | 转发组 / 转发链的搭建、限速与排障 |
| `mmwx-routed-outbound` | 给节点挂落地(路由出站子节点,可一次挂多个)、AI 分流 |
| `mmwx-reverse-tunnel` | 用反向隧道接入 NAT 后面的服务器(家宽落地) |
| `mmwx-cert` | 证书申请 / 续期 / 部署,TLS 节点的 SNI 怎么填 |
| `mmwx-traffic-report` | 流量巡检:总体用量、排行、临近超额的用户 |
| `mmwx-traffic-audit` | 流量对账:某个用户 / 节点的明细、未归属流量、共享账号排查 |
| `mmwx-unlock-routes` | 查节点的流媒体 / AI 解锁与三网回程线路 |
| `mmwx-node-speedtest` | 节点测速 |
| `mmwx-troubleshoot` | 节点连不上、agent 掉线等通用排障 |

## 工具速览(由 MCP server 暴露)

完整清单以客户端 `tools/list` 为准,下面按用途分组列出主要的:

- **服务器**:`server_list` `server_create` `server_update` `server_delete`* `server_system_info` `server_service_status` `server_service_control` `server_inbound_list` `server_inbound_create` `server_inbound_apply` `server_inbound_outbounds` `server_routing_get` `server_routing_update` `server_xray_config_get` `server_xray_test_config` `server_xray_install`* `server_nginx_install`* `server_agent_upgrade` `server_sync_nodes` `server_reality_domains`
- **服务器分组**:`server_group_list` `server_group_create` `server_group_rename` `server_group_assign` `server_group_delete`* `server_inbound_batch_create`
- **节点**:`node_list` `node_get` `node_create` `node_update` `node_delete`* `node_batch_delete`* `node_tcping` `tunnel_list` `node_speedtest` `node_speedtest_results` `speedtest_testers`
- **路由出站与反向隧道**:`routed_outbound_list` `routed_outbound_preview` `routed_outbound_create` `routed_outbound_batch_create` `routed_outbound_rename` `routed_outbound_delete`* `routing_rule_preset_list` `reverse_tunnel_list` `reverse_tunnel_create` `reverse_tunnel_delete`*
- **转发**:`forward_group_*` `forward_chain_*` `forward_status` `forward_metrics`
- **用户与套餐**:`user_list` `user_detail` `user_create` `user_set_status` `user_set_limits` `user_set_traffic_limit` `user_extend` `user_subaccounts` `user_delete`* `package_list` `package_create` `package_update` `package_assign` `package_unassign` `package_batch_assign` `package_assignment_list` `package_assignment_upsert` `package_delete`*
- **订阅与模板**:`subscribe_file_*` `temp_subscription_create` `template_v3_*` `custom_rule_*`
- **流量**:`traffic_summary` `traffic_user_detail` `traffic_server_detail` `traffic_snapshots` `traffic_ledger_user` `traffic_ledger_node` `traffic_ledger_servers` `traffic_ledger_unattributed` `traffic_ledger_user_ips`
- **解锁 / 回程 / 状态**:`node_unlock_list` `node_return_routes` `license_status` `update_check`
- **证书**:`cert_list` `cert_list_valid` `cert_create` `cert_self_signed` `cert_renew` `cert_deploy` `cert_set_auto_renew` `cert_set_auto_deploy` `cert_delete`*
- **运维**:`logs_system` `logs_agent` `task_types` `task_runs` `backup_auto_get` `backup_auto_run` `backup_auto_test` `xray_generate_x25519` `xray_examples`

\* = 高危,需在参数中加 `confirm: true` 才执行。令牌重置 / 清空节点 / 卸载 / 改管理员凭据等高危接口**不暴露**。

> 注意:工具权限随 API 令牌所属账号。普通用户令牌调管理员工具会返回 403。
> 路由出站、反向隧道、解锁 / 回程、流量明细、服务器分组增删改这几组工具需要主控版本晚于 v0.5.6-beta.6。
