#!/bin/bash
# 编译带 Miu 协议出站的 mihomo(源码:公开仓 mmwx-group/meowC 的 core/Clash.Meta),
# 产出 mihomo-miu-<os>-<arch>.gz + checksums.txt,供测速端自动下载(见 mihomo.go 的 miuCoreRepo)。
# 用法:bash scripts/build-mihomo-miu.sh <meowC 仓库路径> [输出目录]
# 发布(tag 必须以 mihomo-miu- 开头;--latest=false 是为了不顶掉测速端自己的 latest release):
#   gh release create mihomo-miu-<版本> <输出目录>/* -R mmwx-group/mmwX-plugins --latest=false \
#     --title "mihomo (Miu) <版本>" --notes "源码:mmwx-group/meowC@<提交> core/Clash.Meta"
set -e

MEOWC="${1:?用法: build-mihomo-miu.sh <meowC 仓库路径> [输出目录]}"
OUT="$(mkdir -p "${2:-./build/mihomo-miu}" && cd "${2:-./build/mihomo-miu}" && pwd)"
SRC="$MEOWC/core/Clash.Meta"
[ -f "$SRC/go.mod" ] || { echo "[ERROR] 找不到 $SRC/go.mod"; exit 1; }
COMMIT=$(git -C "$MEOWC" rev-parse --short HEAD)
# 版本号必须带 miu 字样:测速端靠 `mihomo -v` 的输出认这份内核
VERSION="miu-${COMMIT}"

# meowC 里这份内核是给客户端壳用的:监听端口和 TUN 由壳自己起,ApplyConfig 里那两行被注释掉了,
# 原样编出来的独立二进制读完配置不开任何代理端口。在临时副本里恢复这两行再编,不动 meowC 源码。
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -R "$SRC" "$WORK/core"
EXECUTOR="$WORK/core/hub/executor/executor.go"
sed -i.bak -e 's|^\([[:space:]]*\)// updateListeners(cfg.General, cfg.Listeners, force)|\1updateListeners(cfg.General, cfg.Listeners, force)|' \
           -e 's|^\([[:space:]]*\)// updateTun(cfg.General)|\1updateTun(cfg.General)|' "$EXECUTOR"
rm -f "$EXECUTOR.bak"
if [ "$(grep -cE '^[[:space:]]*update(Listeners|Tun)\(cfg\.General' "$EXECUTOR")" != "2" ]; then
  echo "[ERROR] 没能恢复 updateListeners / updateTun(meowC 那边的写法变了?),编出来的内核不会开端口"; exit 1
fi

cd "$WORK/core"
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  goos=${target%/*}; goarch=${target#*/}
  name="mihomo-miu-${goos}-${goarch}"
  echo "[build] $name ($VERSION)"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -tags with_gvisor \
    -ldflags "-X github.com/metacubex/mihomo/constant.Version=${VERSION} -w -s -buildid=" \
    -o "$OUT/$name" .
  gzip -9 -f "$OUT/$name"
done
cd "$OUT"
shasum -a 256 mihomo-miu-*.gz > checksums.txt
echo "=== 完成: $OUT ==="
ls -la "$OUT"
