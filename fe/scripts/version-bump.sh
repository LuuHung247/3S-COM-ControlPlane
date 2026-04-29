#!/usr/bin/env bash
set -e

# Usage: ./scripts/version-bump.sh patch|minor|major
BUMP="${1:-patch}"

if [[ "$BUMP" != "patch" && "$BUMP" != "minor" && "$BUMP" != "major" ]]; then
  echo "Usage: $0 patch|minor|major"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Bump root package.json (no git tag)
cd "$ROOT_DIR"
NEW_VERSION=$(npm version "$BUMP" --no-git-tag-version | tr -d 'v')
echo "Root: $NEW_VERSION"

# Bump all sub-packages
for pkg in cli desktop mobile; do
  if [ -f "$ROOT_DIR/$pkg/package.json" ]; then
    cd "$ROOT_DIR/$pkg"
    npm version "$NEW_VERSION" --no-git-tag-version --allow-same-version
    echo "$pkg: $NEW_VERSION"
  fi
done

cd "$ROOT_DIR"

# Git commit + tag
git add -A
git commit -m "chore: bump version to v${NEW_VERSION}"
git tag -a "v${NEW_VERSION}" -m "v${NEW_VERSION}"

echo ""
echo "✅ Bumped all packages to v${NEW_VERSION}"
echo "   Run 'git push && git push --tags' to push"
echo "   Run 'cd cli && npm publish' to publish to npm"
