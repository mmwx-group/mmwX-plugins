---
name: mmwx-troubleshoot
description: 排查妙妙屋X的常见故障——节点离线、服务器掉线、xray 未运行、用户订阅异常/无法连接。当用户说"节点连不上""服务器离线了""某用户用不了""xray 挂了"时使用。
---

# 故障排查(妙妙屋X)

目标:定位问题、给出结论与修复建议;只在征得同意后做写操作。

## A. 服务器/服务层面
1. `server_list` 看目标服务器 `status` 与 `xray_running`。
2. 若 connected 但 xray 未运行:`server_service_status`(传 server_id)确认,再向用户确认后用 `server_service_control`(server_id / service=xray / action=restart,**高危需 confirm:true**)。
3. 若服务器 disconnected:多为 agent 掉线/网络问题,提示用户检查该机 agent 与网络(此类不在 agent 可修范围)。

## B. 节点层面
1. `node_list` 找到目标节点,核对其 `server`/`port`/`inbound_tag`。
2. `tunnel_list` 看该节点是否被 tunnel 转发、转发是否正常。
3. 需要时 `server_inbound_list`(传 server_id)核对入站是否存在、配置是否匹配。
4. 怀疑链路速度问题时,触发 `mmwx-node-speedtest` 技能测速佐证。

## C. 用户层面
1. `user_detail`(传 username)看其状态(是否被禁用)、套餐、配额。
2. `traffic_user_detail`(传 username)看是否已超额(超额会被限速/阻断)。
3. 结论可能是:用户被禁用(可 `user_set_status` 启用)、超额(可 `user_set_limits` 或换套餐)、未绑定套餐(`package_assign`)。这些写操作**先和用户确认再做**。

## 注意
- 先诊断、后动手;每个写操作前说明你将做什么。
- 高危操作(重启服务等)需 `confirm: true`。
- 卸载/重置类操作不开放,遇到需要这类处理的情况,给人工指引。
