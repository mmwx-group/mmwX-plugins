---
name: mmwx-traffic-audit
description: 在妙妙屋X里核对流量账——某个用户的流量为什么这么多、和他自己看到的对不上、总量和各用户加起来不一致、怀疑账号被共享。当用户说"流量对不上""帮我查这个用户的流量""谁在用这个节点""有没有共享账号""这部分流量是谁的"时使用。
---

# 流量对账(妙妙屋X)

与 `mmwx-traffic-report`(出概览)不同,这个技能回答的是「**这一笔流量到底是谁的、对不对**」。全程只读。

## 先确认数据是完整的

`task_runs`(`task=traffic_collector`)看采集任务最近有没有失败。明细接口返回里的 `incomplete_dates` 列出了数据不完整的日期,报结论时要说明。

## A. 一个用户的流量

1. `traffic_ledger_user`:`username` + `cycle`(`current` 当前套餐周期 / `prev` 上一周期);要看任意日期就不给 `cycle`,改给 `from` / `to`(`YYYY-MM-DD`)。
   - `by_node`:按节点拆开,看是哪个节点用得多。
   - `by_date`:按天,看是哪几天冲上去的。
   - `packages`:用户有多个套餐实例时,可以再带 `assignment_id` 只看其中一个。
2. 计费量 ≠ 原始字节:套餐是双向计费或节点有倍率时,计费量是加权后的值。跟用户解释时两个数都给。

## B. 一个节点的流量

`traffic_ledger_node`:`node_id` + `from` / `to`,`by_user` 列出每个用户在这个节点上用了多少。

## C. 总量对不上

1. `traffic_ledger_servers`(`from` / `to`):每台服务器的汇总。
2. `traffic_ledger_unattributed`(`from` / `to`):**没有归到任何用户或节点**的流量 —— 系统凭据(中转、转发链出口)、已删除节点的历史流量、Reality 防盗拦下的非法流量等。各用户相加比服务器总量少,差额通常就在这里。

## D. 怀疑账号被共享

1. `traffic_ledger_user_ips`:`username` + `from` / `to`,列出这段时间连接用过的来源 IP(按天、按节点)。
2. 同一天来自多个不同地区或运营商的 IP,是共享的迹象;但移动网络换基站、家宽重拨也会换 IP,不要只凭 IP 数量下结论。
3. `user_subaccounts`(用户名)可以看他在各节点上的凭据标识,配合节点侧日志核对。

## 给结论时

- 写明口径:日期范围(或套餐周期)、是原始量还是计费量。
- 有 `incomplete_dates` 就照实说哪几天数据不全。
- 处理建议只给出、不代为执行:限速用 `user_set_limits`,改流量上限用 `user_set_traffic_limit`,续期用 `user_extend`,都要用户同意后再做。
