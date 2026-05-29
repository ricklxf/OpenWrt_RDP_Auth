#!/bin/bash
# 版本号 +1，重建 IPK，创建 tag，上传到 GitHub Release
# 用法：bash release.sh

set -e
REPO="$(cd "$(dirname "$0")" && pwd)"
VER_FILE="$REPO/VERSION"

# 读取并递增 patch
IFS='.' read -r major minor patch < "$VER_FILE"
NEW_VER="${major}.${minor}.$((patch + 1))"
echo "$NEW_VER" > "$VER_FILE"
echo "Version: $NEW_VER"

# 构建 IPK
cd "$REPO"
python3 build.sh

IPK="$REPO/Port-Control_${NEW_VER}.ipk"
TAG="v${NEW_VER}"

# 提交版本号变更
git add VERSION
git commit -m "chore: bump version to $NEW_VER"
git push

# 创建 tag 并推送
git tag -f "$TAG"
git push origin "$TAG" --force

# 创建或更新 GitHub Release
gh release create "$TAG" --title "$TAG" --notes "Release $TAG" 2>/dev/null || true
gh release upload "$TAG" "$IPK" --clobber

echo "✅ Released $TAG: $IPK"
