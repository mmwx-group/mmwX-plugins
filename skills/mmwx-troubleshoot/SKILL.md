---
name: mmwx-troubleshoot
description: 排查妙妙屋X的常见故障——节点离线、服务器掉线、xray 未运行、用户订阅异常/无法连接。当用户说"节点连不上""服务器离线了""某用户用不了""xray 挂了"时使用。
---

# 故障排查(妙妙屋X)

目标:定位问题、给出结论与修复建议;只在征得同意后做写操作。

## A. 服务器/服务层面
1. `server_list` 看目标服务器 `status` 与 `xray_running`。
2. **资源排查**:`server_system_info`(传 server_id)看 CPU/内存/磁盘是否打满——OOM 或磁盘满会导致 xray 反复挂掉。
3. 若 connected 但 xray 未运行:`server_service_status`(传 server_id)确认,再向用户确认后用 `server_service_control`(server_id / service=xray / action=restart,**高危需 confirm:true**)。
4. 若服务器 disconnected:多为 agent 掉线/网络问题,提示用户检查该机 agent 与网络(此类不在 agent 可修范围)。
5. **同 IP 排查**:`server_check_same_ip` 看是否被重复登记。

## B. 节点层面
1. `node_list` 找到目标节点,`node_get`(传 id)看完整配置;核对其 `server`/`port`/`inbound_tag`。
2. **TCP 连通性诊断**:`node_tcping`(host=节点 server,port=节点端口)从主控视角探测能否打通,排除中间网络问题。
3. `tunnel_list` 看该节点是否被 tunnel 转发、转发是否正常。
4. 需要时 `server_inbound_list`(传 server_id)核对入站是否存在、配置是否匹配。
5. 配置层深挖:`server_xray_config_get`(传 server_id)拉完整 xray 配置看路由/入站细节;`server_routing_get` 看路由规则;`custom_rule_list` 看自定义分流规则是否冲突。
6. 怀疑链路速度问题时,触发 `mmwx-node-speedtest` 技能测速佐证。

## C. 用户层面
1. `user_detail`(传 username)看其状态(是否被禁用)、套餐、配额。
2. `traffic_user_detail`(传 username)看是否已超额(超额会被限速/阻断)。
3. **订阅排查**:`subscribe_file_list` 看该用户是否有可用订阅文件,缺则 `subscribe_file_create`。
4. 结论可能是:用户被禁用(可 `user_set_status` 启用)、超额(可 `user_set_limits` 或换套餐)、未绑定套餐(`package_assign`)、订阅文件缺失(`subscribe_file_create`)。这些写操作**先和用户确认再做**。

## D. 模板/规则配置层面
1. **预览订阅**:若用户报订阅内容异常,用 `template_v3_analyze`(传 subscription_url)分析节点分布,或 `template_v3_preview`(传模板内容 + 节点)直接渲染对比。
2. `custom_rule_list` 看自定义分流是否影响了用户走向(命中 DIRECT 错路等)。

## 注意
- 先诊断、后动手;每个写操作前说明你将做什么。
- 高危操作(重启服务、删用户等)需 `confirm: true`。
- 卸载/重置类操作不开放,遇到需要这类处理的情况,给人工指引。
- `server_xray_config_get` 拉取的是远程服务器的实际生效配置(诊断金标准),与"主控记录的应有配置"比对可发现飘移。
