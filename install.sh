#!/bin/sh
# Install localvault from GitHub releases. Env: VERSION (default latest), INSTALL_DIR (default ~/.local/bin).
set -eu

REPO="exu/localvault"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

fail() { echo "install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unsupported OS $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

command -v curl >/dev/null || fail "curl is required"
command -v tar >/dev/null || fail "tar is required"
if command -v sha256sum >/dev/null; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "sha256sum or shasum is required"
fi

version="${VERSION:-}"
if [ -z "$version" ]; then
  url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || fail "cannot resolve latest release"
  version="${url##*/}"
fi
case "$version" in v*) ;; *) version="v$version" ;; esac

name="localvault_${version}_${os}_${arch}"
base="https://github.com/$REPO/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading localvault $version ($os/$arch)"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || fail "download failed, check that $version exists"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "checksum download failed"

want=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
[ -n "$want" ] || fail "no checksum for $name.tar.gz"
[ "$(sha256 "$tmp/$name.tar.gz")" = "$want" ] || fail "checksum mismatch"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/$name/localvault" "$INSTALL_DIR/localvault"

echo "Installed $INSTALL_DIR/localvault"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Note: $INSTALL_DIR is not on your PATH. Add: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
echo "Next: localvault configure"
