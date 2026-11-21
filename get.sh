#!/bin/sh
# Install or update 3assas from the latest release, no compiler needed:
#   curl -fsSL https://raw.githubusercontent.com/onezdtr/3assas/main/get.sh | sudo sh
set -eu
REPO=onezdtr/3assas
DEST=/opt/3assas
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: curl -fsSL https://raw.githubusercontent.com/$REPO/main/get.sh | sudo sh"; exit 1; }
case $(uname -m) in
x86_64) ARCH=x86_64 ;;
aarch64 | arm64) ARCH=aarch64 ;;
*) echo "no 3assas build for $(uname -m) yet: build from source (see README)"; exit 1 ;;
esac

TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$TAG" ] || { echo "could not find the latest release of $REPO"; exit 1; }
NAME=3assas-$TAG-$ARCH
URL=https://github.com/$REPO/releases/download/$TAG
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "downloading 3assas $TAG ($ARCH)"
curl -fsSL -o "$TMP/$NAME.tar.gz" "$URL/$NAME.tar.gz"
curl -fsSL -o "$TMP/$NAME.tar.gz.sha256" "$URL/$NAME.tar.gz.sha256"
(cd "$TMP" && sha256sum -c --quiet "$NAME.tar.gz.sha256")

# Swap in the new version whole: the agent never runs from a half-extracted tree.
mkdir "$TMP/new"
# Owned by root whatever uid built the archive: a local user with that uid must not edit what root and the agent run.
tar xzf "$TMP/$NAME.tar.gz" -C "$TMP/new" --strip-components=1 --no-same-owner
rm -rf "$DEST.old"
[ -d "$DEST" ] && mv "$DEST" "$DEST.old"
mv "$TMP/new" "$DEST"
chmod 755 "$DEST"
rm -rf "$DEST.old"
"$DEST/install.sh"
