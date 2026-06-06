---
name: mmwx-add-server
description: 在妙妙屋X里接入并初始化一台新的远程服务器——登记服务器、安装 Xray/Nginx、把入站同步成节点。当用户说"加一台服务器""新机器上线""给新 VPS 装好 xray 并出节点"时使用。
---

# 接入新服务器(妙妙屋X)

目标:让一台新服务器在妙妙屋X里可管理、装好代理内核、产出可用节点。

## 步骤

1. **确认信息**:服务器名称、IP/域名、连接模式(push/pull/auto)、监听端口等(向用户索取)。
2. **登记服务器**:`server_create`,参数 `name / ip_address / domain / connection_mode(默认 push)/ listen_port / traffic_limit`。`server_list` 确认其已出现、拿到 `server_id`、查看连接状态。
3. **等待 agent 连上**:轮询 `server_list`,直到该服务器 `status=connected`。SSH 登录该机器执行 agent 安装脚本(用户自己做)。
4. **(可选)看资源**:`server_system_info`(传 server_id)看 CPU/内存/磁盘空间,确认机器健康再继续装服务。
5. **安装 Xray**:`server_xray_install`,参数 `server_id`、`confirm: true`(耗时操作,会等待完成并返回安装日志)。如需 Nginx 同理用 `server_nginx_install`。
6. **核对服务**:`server_service_status`(传 server_id)确认 xray 运行中。
7. **配置入站 → 出节点**:
   - 用 `server_inbound_apply`(action=add,传 inbound 对象)在该服务器创建入站;或让用户在 Web 向导建好。
   - **(推荐)预校验**:`server_xray_test_config`(传 server_id 和 config 对象)dry-run 校验配置语法,避免 apply 后 xray 启动失败。
   - 需要 reality 时:`server_reality_domains`(传 server_id)看候选目标域名,`xray_generate_x25519` 生成密钥对。
   - `server_inbound_list`(传 server_id)核对入站,`server_inbound_outbounds` 核对出站,`server_routing_get` 看路由。
   - `node_create` 把入站手动出节点(或 `server_sync_nodes` 批量同步),`node_list` 可见新节点。
8. **(可选)升级 agent**:若日后该 agent 版本落后主控,`server_agent_upgrade`(server_id + confirm)远程升级(SSE,会短暂失联)。

## 注意
- 安装类是高危写操作,必须带 `confirm: true`;执行可能数分钟,工具会阻塞到完成。
- 卸载 xray/nginx、重置令牌等高危操作**未开放**给 agent,需人工在 Web 端处理。
- 装完若 `server_service_status` 显示未运行,检查安装日志返回里的报错;`server_xray_config_get` 拉取实际配置进一步定位。
- 同 IP 多服务器场景请先用 `server_check_same_ip` 排查重复登记。
