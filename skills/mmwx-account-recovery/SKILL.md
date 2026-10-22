---
name: mmwx-account-recovery
description: 在妙妙屋X里处理账号与凭据类问题——用户忘了密码 / 登不进面板 / 提示稍后再试、IP 被封、订阅链接或节点配置泄露要作废、用户要换订阅短码、超额后手动清零流量、管理员自己的订阅泄露。当用户说"重置密码""登不进去""被锁了""IP 被封""订阅链接被别人拿去用了""换个订阅链接""重置凭据""清一下流量"时使用。
---

# 账号与凭据(妙妙屋X)

这里的操作几乎都会让**旧的东西立即失效**(旧密码、旧凭据、旧链接)。每一步动手前都把影响讲清楚,等用户明确同意再带 `confirm: true` 调用。

## 先判断是哪一类

| 现象 | 先查 | 再做 |
|---|---|---|
| 登不进面板、提示稍后再试 | `security_login_locks` | B |
| 某个 IP 完全打不开面板 / 拉不了订阅 | `security_ban_list`、`security_events`(`ip`) | C |
| 忘了密码 | `user_detail` 确认账号存在且不是管理员 | A |
| 订阅链接或节点配置被分享出去了 | `user_subscription_links`、`traffic_ledger_user_ips` | D |
| 想要一个好记的订阅短码 | `user_detail` 看当前短码 | E |
| 超额被停,要手动恢复 | `traffic_user_detail`、`package_assignment_list` | F |

## A. 重置登录密码

- `user_reset_password`(`username`,`confirm: true`)。不给 `new_password` 时随机生成 12 位,结果里返回新密码。
- 顺带会解开这个账号的登录锁定,不用再单独解锁。
- **管理员的密码不能这样改**(会报错),只能管理员本人在面板「个人设置」里改。
- 新密码只私下发给用户本人。

## B. 登录被锁

1. `security_login_locks` 列出当前的锁:`kind=account`(某个用户名连续输错)或 `kind=ip`(某个 IP 连续输错),带失败次数和解锁时间。
2. `security_login_unlock`(`kind` + `key`,key 是用户名或 IP)解开。
3. 用户其实是忘了密码的话,直接走 A,一步到位。
4. 同一个 IP 对很多账号都在输错,是有人在撞库,不要随手解,先 `security_events`(`ip`)看一下再和用户商量要不要封(C)。

## C. IP 封禁

- 查:`security_ban_list` 看当前生效的封禁(到期时间、是否永久、是谁封的);`security_events`(`ip` / `kind`)看来龙去脉,`kind` 常见值:`login_fail`、`login_locked`、`probe`(暴力探测订阅短码)、`ban`(自动封)、`ban_manual`、`unban`。
- 解:`security_unban_ip`(`ip`),同时清掉这个 IP 的登录锁。
- 封:`security_ban_ip`(`ip`,可选 `permanent`,`confirm: true`)。订阅白名单里的 IP 封不了;**不要封管理员自己的出口 IP 或受管服务器的地址**,封之前确认清楚。

## D. 链接 / 节点配置泄露

按影响从小到大选:

1. **只换节点凭据**:`user_reset_credentials`(`username`,`confirm: true`)。旧凭据立即失效、在用的连接会断;订阅链接不变,用户在客户端「更新订阅」就能继续用。适合「分享出去的是节点配置 / 二维码」。
2. **凭据 + 订阅链接一起换**:再加 `rotate_links: true`。订阅 token、用户短码、套餐短码全部换新,旧链接从此打不开。适合「订阅链接本身被分享了」。做完用 `user_subscription_links` 拿新链接发给用户。
3. **管理员自己的订阅泄露**:`admin_reset_own_credentials`(`confirm: true`)。换的是当前令牌所属管理员自己的凭据和订阅链接,管理员自己的客户端要重新导入;API 令牌不受影响。

注意:

- 相关服务器必须全部在线,否则会报错、不会只换一半;`server_list` 先看一眼。
- 判断有没有被共享:`traffic_ledger_user_ips`(`username` + 日期)看来源 IP,同一天多个地区 / 运营商是迹象,但手机换基站、家宽重拨也会换 IP。

## E. 换订阅短码

- `user_set_short_code`(`username` + `short_code`,`confirm: true`):字母 / 数字 / `_` / `-`,2-16 位,不能和别的用户名或短码冲突;`short_code` 留空 = 清掉自定义短码。
- **不论设置还是清空,订阅 token 和系统短码都会一起轮换**,用户以前的所有订阅链接全部失效。做完 `user_subscription_links` 拿新链接发给用户。

## F. 手动清零流量

- `user_reset_traffic`(`username`,`confirm: true`):把本周期已用流量清零,因超额被停的会恢复;累计总量和流量明细不受影响。
- 清零前先说清楚这次是「送流量」还是「周期本该重置但没重置」:后者先 `package_assignment_list` 看重置日 / 到期时间对不对,配置错了要改套餐实例(`package_assignment_upsert`),否则下个周期还会出问题。
- 只想临时多给一点,用 `user_set_traffic_limit` 提额比清零更容易追溯。

## 注意

- 这些操作都按调用方的 API 令牌鉴权,普通用户令牌调用会返回 403。
- 新密码、新订阅链接只发给用户本人,不要发到群聊或公开频道。
- 做完告诉用户:改了什么、旧的什么已经失效、他接下来要做什么(更新订阅 / 重新导入 / 用新密码登录)。
