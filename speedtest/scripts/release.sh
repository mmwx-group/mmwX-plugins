#!/bin/bash
# mmwx-speedtester 一键发布:bump VERSION -> 更新 README changelog -> commit -> tag(speedtest-vX.Y.Z) -> push -> 创建 GitHub Release
# GitHub Action(.github/workflows/speedtest.yml)会在该 tag 上自动多平台打包并上传二进制。
# 用法:bash scripts/release.sh [patch|minor|major]   (默认 patch)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"   # .../mmwX-plugins/speedtest
REPO_ROOT="$(dirname "$PLUGIN_DIR")"    # .../mmwX-plugins
cd "$REPO_ROOT"

BUMP="${1:-patch}"

# 1. bump 版本
CUR=$(cat "$PLUGIN_DIR/VERSION" | tr -d '[:space:]')
IFS='.' read -r MAJ MIN PAT <<< "$CUR"
case "$BUMP" in
  major) MAJ=$((MAJ+1)); MIN=0; PAT=0 ;;
  minor) MIN=$((MIN+1)); PAT=0 ;;
  patch) PAT=$((PAT+1)) ;;
  *) echo "[ERROR] 未知 bump 类型: $BUMP (patch|minor|major)"; exit 1 ;;
esac
NEW_VERSION="${MAJ}.${MIN}.${PAT}"
TAG="speedtest-${NEW_VERSION}"
echo "[1/5] 版本 ${CUR} -> ${NEW_VERSION}"
echo "$NEW_VERSION" > "$PLUGIN_DIR/VERSION"

# 2. changelog:取自上个 speedtest tag 以来、改动了 speedtest/ 的 commit
PREV_TAG=$(git describe --tags --match 'speedtest-v*' --abbrev=0 2>/dev/null || echo "")
if [ -n "$PREV_TAG" ]; then
  RANGE="${PREV_TAG}..HEAD"
else
  RANGE="HEAD"
fi
COMMITS=$(git log $RANGE --pretty=format:"- %s" --no-merges -- speedtest/ | grep -v "^- speedtest-v[0-9]" | sort -u || true)
[ -z "$COMMITS" ] && COMMITS="- maintenance release"
echo "=== 变更 ==="; echo "$COMMITS"; echo ""

# 3. 更新 README changelog(插入到 <summary>更新日志</summary> 之后)
echo "[2/5] 更新 README changelog..."
TODAY=$(date +%Y-%m-%d)
TMP=$(mktemp)
{ echo ""; echo "### v${NEW_VERSION} (${TODAY})"; echo "$COMMITS"; } > "$TMP"
INSERT_LINE=$(grep -n '<summary>更新日志</summary>' "$PLUGIN_DIR/README.md" | head -1 | cut -d: -f1)
if [ -n "$INSERT_LINE" ]; then
  { head -n "$INSERT_LINE" "$PLUGIN_DIR/README.md"; cat "$TMP"; tail -n +"$((INSERT_LINE+1))" "$PLUGIN_DIR/README.md"; } > "$PLUGIN_DIR/README.md.tmp"
  mv "$PLUGIN_DIR/README.md.tmp" "$PLUGIN_DIR/README.md"
fi
rm -f "$TMP"

# 4. commit + tag + push
echo "[3/5] commit + tag ${TAG}..."
git add speedtest/VERSION speedtest/README.md
git commit -m "speedtest ${TAG}" --no-verify
git tag "$TAG"
echo "[4/5] push..."
git push origin "$(git rev-parse --abbrev-ref HEAD)"
git push origin "$TAG"

# 5. GitHub Release(Action 随后上传二进制)
echo "[5/5] 创建 GitHub Release..."
RELEASE_BODY="## mmwx-speedtester ${TAG}

### v${NEW_VERSION} (${TODAY})
${COMMITS}

家用测速端:在你家里的机器运行,反向连入主控,从家庭网络视角对节点测速。
用法见 speedtest/README.md。"
gh release create "$TAG" --title "speedtest v${NEW_VERSION}" --notes "$RELEASE_BODY"

echo ""
echo "=== 发布完成! ${TAG} ==="
echo "  GitHub Action 将自动多平台打包(linux/windows/darwin × amd64/arm64)并上传到该 Release"
