#!/bin/bash
# 编译带 Miu 协议出站(第二版)的 mihomo,产出 mihomo-miu-<os>-<arch>.gz + checksums.txt,
# 供测速端自动下载(见 mihomo.go 的 miuCoreRepo)。
# 源码:https://github.com/MiuProtocol/mihomo 的 Alpha 分支(上游 mihomo + Miu 出站),先克隆到本地:
#   git clone --depth 1 -b Alpha https://github.com/MiuProtocol/mihomo.git
# 用法:bash scripts/build-mihomo-miu.sh <mihomo 源码路径> [输出目录]
# 发布(tag 必须以 mihomo-miu-v2- 开头;--latest=false 是为了不顶掉测速端自己的 latest release):
#   gh release create mihomo-miu-v2-<提交> <输出目录>/* -R mmwx-group/mmwX-plugins --latest=false \
#     --title "mihomo (Miu v2) <提交>" --notes "源码:MiuProtocol/mihomo@<提交>(Alpha)"
set -e

SRC="$(cd "${1:?用法: build-mihomo-miu.sh <mihomo 源码路径> [输出目录]}" && pwd)"
OUT="$(mkdir -p "${2:-./build/mihomo-miu}" && cd "${2:-./build/mihomo-miu}" && pwd)"
[ -f "$SRC/go.mod" ] || { echo "[ERROR] 找不到 $SRC/go.mod"; exit 1; }
[ -f "$SRC/adapter/outbound/miu.go" ] || { echo "[ERROR] $SRC 里没有 Miu 出站(adapter/outbound/miu.go),不是带 Miu 的 mihomo"; exit 1; }
COMMIT=$(git -C "$SRC" rev-parse --short HEAD)
# 版本号必须以 miu2- 开头:测速端靠 `mihomo -v` 的输出认这份内核,并据此把第一版(miu-<提交>)的换掉。
# r<修订> 是内核能力的修订号,与 mihomo.go 的 miuCoreMinRev 对应:给内核补了测速端要用到的新能力时两边一起加一
# (测速端发现本地内核修订不够就会换新包)。2 = AnyTLS 支持 REALITY。
REV=2
VERSION="miu2-r${REV}-${COMMIT}"

cd "$SRC"
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  goos=${target%/*}; goarch=${target#*/}
  name="mihomo-miu-${goos}-${goarch}"
  echo "[build] $name ($VERSION)"
  # 固定用 Go 1.26 编(上游 mihomo 的 CI 也是 1.26):Go 1.27.0 编出来的包在部分机器上
  # (内核 6.18-rc 的 x86_64 路由器)一加载就段错误,-v 都跑不出来,换 1.26.2 重编后正常。
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch GOTOOLCHAIN="${MIU_GO_TOOLCHAIN:-go1.26.2}" go build -trimpath -tags with_gvisor \
    -ldflags "-X github.com/metacubex/mihomo/constant.Version=${VERSION} -w -s -buildid=" \
    -o "$OUT/$name" .
  gzip -9 -f "$OUT/$name"
done
cd "$OUT"
shasum -a 256 mihomo-miu-*.gz > checksums.txt
echo "=== 完成: $OUT ==="
ls -la "$OUT"
