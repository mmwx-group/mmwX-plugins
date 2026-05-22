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

### v0.0.2 (2026-05-22)
- 🌈主控测速插件
</details>
