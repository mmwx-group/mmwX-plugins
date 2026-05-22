---
name: mmwx-add-server
description: 在妙妙屋X里接入并初始化一台新的远程服务器——登记服务器、安装 Xray/Nginx、把入站同步成节点。当用户说"加一台服务器""新机器上线""给新 VPS 装好 xray 并出节点"时使用。
---

# 接入新服务器(妙妙屋X)

目标:让一台新服务器在妙妙屋X里可管理、装好代理内核、产出可用节点。

## 步骤

1. **确认信息**:服务器名称、IP、SSH 端口/用户/密码、xray 模式等(向用户索取)。
2. **登记服务器**:经 REST `POST /api/admin/remote-servers/create`(若未提供对应工具,可让用户在 Web 端添加;本技能聚焦后续初始化)。`server_list` 确认其已出现、拿到 `server_id`、查看连接状态。
3. **等待 agent 连上**:轮询 `server_list`,直到该服务器 `status=connected`。
4. **安装 Xray**:`server_xray_install`,参数 `server_id`、`confirm: true`(耗时操作,会等待完成并返回安装日志)。如需 Nginx 同理用 `server_nginx_install`。
5. **核对服务**:`server_service_status`(传 server_id)确认 xray 运行中。
6. **配置入站 →出节点**:
   - 用 `server_inbound_apply`(action=add,传 inbound 对象)在该服务器创建入站;或让用户在 Web 向导建好。
   - `server_inbound_list`(传 server_id)核对入站。
   - `server_sync_nodes`(传 server_id)把入站同步进节点管理,之后 `node_list` 可见新节点。

## 注意
- 安装类是高危写操作,必须带 `confirm: true`;执行可能数分钟,工具会阻塞到完成。
- 卸载 xray/nginx、重置令牌等高危操作**未开放**给 agent,需人工在 Web 端处理。
- 装完若 `server_service_status` 显示未运行,检查安装日志返回里的报错再决定是否重试。
