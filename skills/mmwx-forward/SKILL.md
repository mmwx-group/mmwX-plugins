---
name: mmwx-forward
description: 在妙妙屋X里搭建与运维转发链——建转发组/链、把节点绑到入口端口、设限速与连接数、排查转发不通。当用户说"做个中转""加一条转发链""落地机走中转""转发不通""端口被占了"时使用。
---

# 转发链(妙妙屋X)

目标:把「客户端 → 入口机 → (可选中间机) → 落地」这条链路搭起来并能持续运维。

## 概念(先分清,不然会绕）

- **转发组**:一组服务器 + 均衡策略。链的每一跳是一个组,组里多台就是这一跳的负载均衡。
- **转发链**:有序的组列表。**第一个组是入口,最后一个是出口**。只有入口组的单组链也是合法的——「一台预设入口 + 用户自己的节点」就是这种形态。
- **绑定**:把一个节点绑到链的某个入口端口上。之后客户端连的是「入口机:端口」,流量顺着链走到落地。
- **计费口径**:只算**入口那一跳**,再乘链的流量倍率。不是每跳都算 —— 跟用户解释账单时要说清楚。

## A. 搭一条链

1. **看现状**:`forward_group_list` 看已有的组,`forward_chain_list` 看已有的链,别重复建。
2. **建组**:`forward_group_create`,给 `name` 和 `members`(元素 `{server_id, weight, seq}`,seq 决定组内顺序)。
   - `balance_strategy`:`round_robin`(默认)/ `percentage` / `cycle`。
   - 要做 DNS 负载均衡再给 `dns_domain` + `dns_provider_id`;只作中间/出口跳的组留空即可。
3. **建链**:`forward_chain_create`,`name` + `group_ids`(**按跳顺序,入口在前**),并给 `port_range_start` / `port_range_end` 划定入口端口区间。
4. **绑节点**:
   - 已有节点走这条链:`forward_chain_bind_node`(`chain_id` + `node_id`,`port` 留空让主控在区间内自动分配)。
   - 想直接生成一个可加进订阅的入口节点:`forward_chain_create_node`,给 `existing_node_id` 表示中继到已有节点(会用**该用户自己的**凭据),不给则由出口组自建站。
5. **下发**:`forward_chain_apply`(`chain_id`)。**不做这一步,前面所有改动都不会生效。**
6. **核对**:`forward_status` 看规则是否下发成功、监听是否起来。

## B. 限速与配额

1. 单条绑定的限制:`forward_chain_set_limit`(`chain_id` + `node_id` + `rate_mbps` / `conn_limit` / `ip_limit`,0 表示不限)。
2. 改完同样要 `forward_chain_apply` 才生效。
3. 套餐维度的转发配额(能建几条、限速多少)在套餐里配,不在这套工具里改。

## C. 排障

1. `forward_status` —— 第一站。看每台服务器上规则的下发状态与监听。
2. 规则在、但连不上:`forward_chain_connections`(`chain_id`)看实时连接,区分「没连上」还是「连接数打满」。
3. 想看历史:`forward_metrics`(`server_id` + `rule_id`,rule_id 从 `forward_status` 取,形如 `fwd-c7-p30082-h0`)。
4. 链结构本身有问题:`forward_chain_get`(`chain_id`)会返回结构完整性问题列表(缺跳、组为空等)。
5. 落地机上的实际情况:`logs_agent`(`server_id`,`service=agent`)读远端日志。

### 常见坑

- **改了不下发**:改组成员、改跳序、改限额之后没 `forward_chain_apply`,是转发类问题最常见的原因。
- **端口被占**:入口端口分配走链的端口区间;区间太窄或被别的进程占了会建不出来。让主控自动分配,别手工指定。
- **删组删不掉**:被链引用的组必须先改链的跳(`forward_chain_set_hops`)才能删。
- **单组链**:只有入口组是合法的,不要为了凑两跳去建一个空的出口组。

## 注意

- 删链、删组、解绑都是高危操作,需要 `confirm: true`;删链会让链上已绑定的节点一并失效。
- 改动前先 `forward_chain_get` / `forward_group_get` 把现状读出来给用户确认,再动手。
- 出口如果是别人套餐里的节点,凭据由主控按**发起转发的那个用户**解析,不要手工去抄目标节点的配置。
