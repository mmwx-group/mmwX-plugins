---
name: mmwx-onboard-user
description: 在妙妙屋X里开通一个新用户的完整流程——创建账号、选择或新建套餐、绑定、生成订阅链接。当用户说"开通/新增一个用户""给某人开个套餐""新建账号并配置好节点"时使用。
---

# 开通新用户(妙妙屋X)

目标:从零给一个新用户配好可用的订阅。

## 步骤

1. **确认信息**:向用户索取 用户名、初始密码;问清要绑定的套餐(已有套餐名,或新建套餐的参数:流量 GB、周期天数、包含哪些节点、是否限速/限设备)。
2. **看现有资源**(只读):
   - `package_list` 看是否已有合适套餐。
   - 需要选节点时 `node_list` 看可用节点及其 ID。
3. **(可选)新建套餐**:`package_create`,参数 `name / traffic_limit_gb / cycle_days / nodes(节点ID数组) / traffic_mode(oneway|twoway) / speed_limit_mbps / device_limit`。记下返回的套餐 ID。
4. **创建用户**:`user_create`,参数 `username / password`(可带 `email / nickname`)。
5. **绑定套餐**:`package_assign`,参数 `username / package_id`(可带 `start_date / expire_date`,格式 YYYY-MM-DD;不传则用默认周期)。
6. **核对**:`user_detail`(传 username)确认套餐、配额、订阅信息已生成。
7. **交付**:把订阅信息告诉用户。如需临时/限时订阅,用 `temp_subscription_create`。

## 注意
- 绑定套餐会异步生成订阅文件并下发入站凭据,核对前可稍等。
- 不要把密码明文回显在公开频道。
- 若 `user_create` 报用户名已存在,改用其它用户名或先 `user_list` 核对。
