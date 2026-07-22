# mmwx-speedtester · 妙妙屋X 家用测速端

妙妙屋X PRO「节点测速」功能的家用测速端(Phase 2)。部署在你家里的服务器/电脑上,
**主动反向连接主控**(解决家庭无公网 IP、主控无法主动访问的问题);收到主控派发的
测速任务后,用 [mihomo](https://github.com/MetaCubeX/mihomo) 内核对指定节点下载测速,
结果经同一连接回传。从而得到「你家这条网络 → 节点」的真实速度。

## 使用

1. 在妙妙屋X 主控「节点测速 → 管理测速端」生成一个**配对令牌**。
2. 在你家里的机器上运行(支持 Linux / Windows / macOS,amd64/arm64):

```bash
# Linux / macOS
./mmwx-speedtester -master https://你的主控地址 -token <配对令牌> -name 家里

# Windows
mmwx-speedtester-windows-amd64.exe -master https://你的主控地址 -token <配对令牌> -name 家里
```

也可用环境变量:`MMWX_MASTER` / `MMWX_SPEEDTEST_TOKEN` / `MMWX_SPEEDTEST_NAME`。

3. 主控「节点测速」下拉即可看到该测速端,选它即可从家庭网络视角测速。

> 首次测速会自动下载对应平台的 mihomo 内核(缓存到运行目录的 `data/bin/`)。

## 构建

```bash
go build -o mmwx-speedtester .
# 交叉编译 Windows
GOOS=windows GOARCH=amd64 go build -o mmwx-speedtester.exe .
```

发布:`bash scripts/release.sh [patch|minor|major]`(打 `speedtest-vX.Y.Z` tag,GitHub Action 自动多平台打包)。

<details>
<summary>更新日志</summary>

### vv0.1.4 (2026-07-22)
- 🌈 支持服务器IP可用性探测

### vv0.1.3 (2026-07-20)
- 🌈 支持设置缓冲区大小

### vv0.1.2 (2026-07-08)
- fix 脚本错误

### vv0.1.1 (2026-07-08)
- speedtest支持snell mihomo

### vv0.1.0 (2026-06-10)
- 🌈增加自动重连与docker镜像打包

### v0.0.9 (2026-06-06)
- 🌈增加链接日志

### v0.0.8 (2026-05-26)
- 🌈优化单线程测速

### v0.0.7 (2026-05-26)
- Update install.sh
- 🌈 支持延迟测试

### v0.0.6 (2026-05-26)
- 🌈测速的时间改为8秒

### v0.0.5 (2026-05-26)
- 🌈测速的时间改为15秒

### v0.0.4 (2026-05-26)
- 🌈增加测速安装脚本
- 🌈支持多线程测速

### v0.0.3 (2026-05-23)
- 🌈测速结果支持出口IP显示

### v0.0.2 (2026-05-22)
- 🌈主控测速插件
</details>
