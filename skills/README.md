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
`MCP server 'miaomiaowux' (HTTP): registered 26 tool(s)`。已在 Telegram 渠道实测对话可调用。

> 其它兼容 MCP 的客户端(Claude Code、Cursor 等)同理:填 `/mcp` 的 URL + Bearer 头即可。

## 工具速览(由 MCP server 暴露)

- 只读:`node_list` `tunnel_list` `subscribe_file_list` `traffic_summary` `traffic_user_detail` `server_list` `server_service_status` `server_inbound_list` `user_list` `user_detail` `package_list`
- 写:`user_create` `user_set_status` `user_set_limits` `user_delete`* `package_create` `package_assign` `package_unassign` `temp_subscription_create` `node_speedtest` `node_delete`* `server_service_control` `server_inbound_apply` `server_xray_install`* `server_nginx_install`* `server_sync_nodes`

\* = 高危,需在参数中加 `confirm: true` 才执行。令牌重置 / 清空节点 / 卸载 / 改管理员凭据等高危接口**不暴露**。

> 注意:工具权限随 API 令牌所属账号。普通用户令牌调管理员工具会返回 403。
