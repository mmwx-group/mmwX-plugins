# 妙妙屋X Claude Agent Skills

一组 Claude Agent Skills,配合妙妙屋X主控内置的 MCP server 使用,让 agent(如 OpenClaw)用自然语言完成常见运维。

## 前置:接好 MCP

### 一键接入(推荐)

1. 在妙妙屋X **个人设置 → API 令牌** 生成一枚令牌(权限与你的账号一致)。
2. 点「**复制给 AI Agent 一键接入**」,把复制的整段话发给你的 agent(Claude Code、Codex、OpenClaw、Hermes、Cursor 等)。
3. agent 会自己:用 `license_status` 验证令牌 → 按它自己的客户端写好 MCP 配置 → 把本目录的技能装进它的 skills 目录 → 重载后核对工具数。不能自己重启的客户端会告诉你怎么做。

这段话里含令牌明文,只发给你自己的 agent。已有令牌但没保存明文的,也可以直接点复制,agent 会先向你要令牌。

### 手动配置

MCP 地址是 `https://你的主控/mcp`(Streamable HTTP,无状态),鉴权用请求头 `Authorization: Bearer <令牌>`。装 xray / nginx、升级 agent 这类工具会跑好几分钟,工具超时设到 600 秒以上。

**Claude Code**
```bash
claude mcp add --transport http --scope user miaomiaowux https://你的主控/mcp --header "Authorization: Bearer <你的 API 令牌>"
```
技能放进 `~/.claude/skills/`(把本目录的 `mmwx-*` 整个复制过去)。

**Codex**(`~/.codex/config.toml`)
```toml
[mcp_servers.miaomiaowux]
url = "https://你的主控/mcp"
http_headers = { "Authorization" = "Bearer <你的 API 令牌>" }
tool_timeout_sec = 600
```

**OpenClaw**(`openclaw.json`)
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

**Hermes Agent**(`~/.hermes/config.yaml`,顶层加 `mcp_servers`)
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
加完**重启 hermes**(MCP 在启动时连接);成功后日志会出现 `MCP server 'miaomiaowux' (HTTP): registered N tool(s)`。

**Cursor**(`~/.cursor/mcp.json`)
```json
{ "mcpServers": { "miaomiaowux": { "url": "https://你的主控/mcp", "headers": { "Authorization": "Bearer <你的 API 令牌>" } } } }
```

其它兼容 MCP 的客户端同理:填 `/mcp` 的 URL + Bearer 头即可。OpenClaw / Hermes 把技能放进 agent 工作区的 skills 目录;不支持技能目录的客户端(Codex、Cursor)可以把本文件和对应的 `SKILL.md` 当参考资料交给它。

**验证**:调用只读工具 `license_status`。返回 `HTTP 401` = 令牌不对或已删除;`HTTP 403` = 令牌所属账号不是管理员。

## 技能一览

| 技能 | 用来做什么 |
|---|---|
| `mmwx-add-server` | 接入一台新服务器、装 xray / nginx、建第一个入站 |
| `mmwx-onboard-user` | 开用户、分配套餐、发订阅 |
| `mmwx-account-recovery` | 重置密码 / 凭据 / 订阅链接 / 流量,登录解锁,IP 封禁与解封 |
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

共 155 个,完整清单以客户端 `tools/list` 为准:

- **服务器**:`server_agent_upgrade`* `server_create` `server_delete`* `server_inbound_apply` `server_inbound_batch_create` `server_inbound_create` `server_inbound_list` `server_inbound_outbounds` `server_list` `server_nginx_install`* `server_reality_domains` `server_routing_get` `server_routing_update`* `server_service_control`* `server_service_status` `server_sync_nodes` `server_system_info` `server_update` `server_xray_config_get` `server_xray_install`* `server_xray_test_config`
- **服务器分组**:`server_group_assign` `server_group_create` `server_group_delete`* `server_group_list` `server_group_rename`
- **节点**:`node_batch_delete`* `node_create` `node_delete`* `node_get` `node_list` `node_return_routes` `node_speedtest` `node_speedtest_results` `node_tcping` `node_unlock_list` `node_update`
- **路由出站与反向隧道**:`reverse_tunnel_create` `reverse_tunnel_delete`* `reverse_tunnel_list` `routed_outbound_batch_create` `routed_outbound_create` `routed_outbound_delete`* `routed_outbound_list` `routed_outbound_preview` `routed_outbound_rename` `routing_rule_preset_list` `tunnel_list`
- **转发**:`forward_chain_apply` `forward_chain_bind_node` `forward_chain_connections` `forward_chain_create` `forward_chain_create_node` `forward_chain_delete`* `forward_chain_get` `forward_chain_list` `forward_chain_rebind_node` `forward_chain_set_hops` `forward_chain_set_limit` `forward_chain_speed_test_cancel` `forward_chain_speed_test_history` `forward_chain_speed_test_start` `forward_chain_speed_test_status` `forward_chain_unbind_node`* `forward_chain_update` `forward_group_create` `forward_group_delete`* `forward_group_get` `forward_group_list` `forward_group_set_members` `forward_group_update` `forward_metrics` `forward_status`
- **用户与套餐**:`admin_reset_own_credentials`* `package_assign` `package_assignment_list` `package_assignment_upsert` `package_batch_assign` `package_create` `package_delete`* `package_list` `package_unassign` `package_update` `user_create` `user_delete`* `user_detail` `user_extend` `user_list` `user_reset_credentials`* `user_reset_password`* `user_reset_traffic`* `user_set_email` `user_set_limits` `user_set_remark` `user_set_short_code`* `user_set_status` `user_set_traffic_limit` `user_subaccounts` `user_subscription_links`
- **安全**:`security_ban_ip`* `security_ban_list` `security_events` `security_login_locks` `security_login_unlock` `security_unban_ip`
- **订阅与模板**:`custom_rule_create` `custom_rule_delete`* `custom_rule_get` `custom_rule_list` `custom_rule_preview` `custom_rule_update` `rule_template_get` `rule_template_list` `subscribe_file_delete`* `subscribe_file_get` `subscribe_file_import` `subscribe_file_list` `subscribe_file_update` `temp_subscription_create` `template_v3_analyze` `template_v3_list` `template_v3_preview` `template_v3_preview_with_tags`
- **流量**:`traffic_ledger_node` `traffic_ledger_servers` `traffic_ledger_unattributed` `traffic_ledger_user` `traffic_ledger_user_ips` `traffic_server_detail` `traffic_snapshots` `traffic_summary` `traffic_user_detail`
- **证书**:`cert_create` `cert_delete`* `cert_deploy` `cert_list` `cert_list_valid` `cert_renew` `cert_self_signed` `cert_set_auto_deploy` `cert_set_auto_renew`
- **运维与状态**:`backup_auto_get` `backup_auto_run` `backup_auto_test` `license_status` `logs_agent` `logs_agent_files` `logs_files` `logs_system` `speedtest_testers` `task_runs` `task_types` `update_check` `xray_examples` `xray_generate_x25519`

\* = 高危,需在参数中加 `confirm: true` 才执行,agent 应先征得用户同意。卸载 xray / nginx、清空节点、重置 agent 令牌等接口**不暴露**。

> 注意:工具权限随 API 令牌所属账号。普通用户令牌调管理员工具会返回 403。
> 账号与安全类工具(`user_reset_*`、`user_set_short_code`、`user_subscription_links`、`admin_reset_own_credentials`、`security_*`)以及 `subscribe_file_import`、`custom_rule_preview`、`template_v3_preview_with_tags` 需要主控 v0.5.9 及以后;v0.5.8 及更早的主控上这些工具不存在,`subscribe_file_create` / `custom_rule_apply` 是它们的旧名(旧版参数和后端对不上,建议升级)。
