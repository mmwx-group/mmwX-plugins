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
5. **同 IP 排查**:`server_list` 返回里比对各服务器的 `ip_address` 与 `same_host_as_master`,看是否有重复登记(同一台机器被加了两次会触发 agent_token 抢占,双方反复互踢)。

## B. 节点层面
1. `node_list` 找到目标节点,`node_get`(传 id)看完整配置;核对其 `server`/`port`/`inbound_tag`。
2. **TCP 连通性诊断**:`node_tcping`(host=节点 server,port=节点端口)从主控视角探测能否打通,排除中间网络问题。
3. `tunnel_list` 看该节点是否被 tunnel 转发、转发是否正常。
4. 需要时 `server_inbound_list`(传 server_id)核对入站是否存在、配置是否匹配。
5. 配置层深挖:`server_xray_config_get`(传 server_id)拉完整 xray 配置看路由/入站细节;`server_routing_get` 看路由规则;`custom_rule_list` 看自定义分流规则是否冲突。
6. 怀疑链路速度问题时,触发 `mmwx-node-speedtest` 技能测速佐证。

## B2. 日志(定位到具体报错)
1. `logs_system`(可带 `level=ERROR` / `q=关键字` / `lines`)读主控日志——大部分故障的第一手材料都在这。
2. `logs_agent`(`server_id`,可带 `service=xray|agent|nginx` 与 `lines`)读远端 agent/xray 的日志;`logs_agent_files` 看有哪些日志文件可读。
3. `task_runs`(可带 `task` / `status`)看定时任务有没有在跑、有没有连续失败——「流量不涨」「服务器显示离线」经常是采集任务挂了而不是节点坏了。

## B3. 转发链层面(节点走转发时)
1. `forward_status` 先看全局:每台转发服务器的规则是否下发成功、监听是否起来。转发排障第一站。
2. `forward_chain_list` / `forward_chain_get`(`chain_id`)看链的跳序与结构问题列表;`forward_group_list` 看每一跳的组里有哪些服务器。
3. `forward_chain_connections`(`chain_id`)看实时连接——「连不上」要区分是没连上还是连接数打满了。
4. `forward_metrics`(`server_id` + `rule_id`,rule_id 从 `forward_status` 里取)看这条规则的历史流量与延迟曲线。
5. 改完组成员/跳序/限额,必须 `forward_chain_apply`(`chain_id`)才会真正下发生效——只改不下发是转发类问题的高频原因。

## B4. 证书层面
1. `cert_list` 看目标域名的证书是否过期、自动续期与自动部署是否开着。TLS 类入站在证书过期后会直接连不上。
2. 确认过期后:`cert_renew`(`id`)续期,再 `cert_deploy`(`id`)部署到 nginx/xray;两者都做完才生效。

## C. 用户层面
1. `user_detail`(传 username)看其状态(是否被禁用)、套餐、配额。
2. `package_assignment_list`(传 username)看**多套餐实例**分配(现在的主路径):到期时间、流量覆盖、是否 active。只看 `user_detail` 会漏掉走套餐实例绑定的那些。
3. `traffic_user_detail`(传 username)看是否已超额(超额会被限速/阻断)。
4. **订阅排查**:`subscribe_file_list` 看该用户是否有可用订阅文件,缺则 `subscribe_file_create`。
5. 结论可能是:用户被禁用(可 `user_set_status` 启用)、超额(可 `user_set_limits` 或换套餐)、未绑定套餐(`package_assign`)、订阅文件缺失(`subscribe_file_create`)。这些写操作**先和用户确认再做**。

## D. 模板/规则配置层面
1. **预览订阅**:若用户报订阅内容异常,用 `template_v3_analyze`(传 subscription_url)分析节点分布,或 `template_v3_preview`(传模板内容 + 节点)直接渲染对比。
2. `custom_rule_list` 看自定义分流是否影响了用户走向(命中 DIRECT 错路等)。

## 注意
- 先诊断、后动手;每个写操作前说明你将做什么。
- 高危操作(重启服务、删用户等)需 `confirm: true`。
- 卸载/重置类操作不开放,遇到需要这类处理的情况,给人工指引。
- `server_xray_config_get` 拉取的是远程服务器的实际生效配置(诊断金标准),与"主控记录的应有配置"比对可发现飘移。
- 路由确实需要改时用 `server_routing_update`(`action=set|add_rule|remove_rule`,**高危需 confirm:true**)。删规则优先用 `marktag` 或 `outbound_tag` 定位,**别只给 index** —— 规则顺序会漂,按下标删很容易删错一条。
