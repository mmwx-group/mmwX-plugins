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
5. **绑定套餐**:优先用 `package_assignment_upsert`(`username / package_id`,可带 `package_start_date / package_end_date / is_reset / reset_day / traffic_limit_override / is_primary`)—— 这是**套餐实例**口径,一个用户可以同时绑多个套餐,现在的主路径。
   老的 `package_assign` 走 `users.package_id` 单套餐口径,只在明确要那套老行为时才用;两者混用会让用户端算出来的额度对不上。
6. **核对**:`user_detail`(传 username)看账号状态,再用 `package_assignment_list`(传 username)确认套餐实例已建好、到期时间与额度正确。
7. **(可选)补 email / 备注**:`user_set_email`、`user_set_remark` 把用户信息补全(都是覆盖式更新,会写入 db)。
8. **生成订阅文件**:`subscribe_file_create`,必填 `username`,可选:
   - `template_id` 或 `template_filename` 绑定 V3 模板(先 `template_v3_list` 看可选模板)
   - `custom_short_code` 自定义短码(字母/数字/_/- 长度 2-16)
   - `selected_tags` V3 模板下的节点筛选标签
   - `remark` 备注
   返回的 short_code 拼成订阅 URL 给用户。`subscribe_file_list` 可复核结果。
9. **交付**:把订阅 URL 告诉用户。如需临时/限时订阅,用 `temp_subscription_create`。

## 注意
- 绑定套餐会异步下发入站凭据,核对前可稍等。
- **一个用户绑多个套餐是常态**:核对额度、排查"流量对不上"时要用 `package_assignment_list` 看全部实例,只看 `user_detail` 会漏。
- **订阅文件必须显式 `subscribe_file_create` 创建**——绑套餐本身不会自动生成订阅文件。
- 不要把密码明文回显在公开频道。
- 若 `user_create` 报用户名已存在,改用其它用户名或先 `user_list` 核对。
- 改订阅模板/筛选标签可用 `subscribe_file_update` 在线调整(无需重建)。
