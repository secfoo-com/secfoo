#!/bin/sh
# Universal installer for secfoo (macOS/Linux). Usage:
#   curl -fsSL https://raw.githubusercontent.com/rakfortltd/secfoo/main/install.sh | sh
#
# Downloads the correct standalone binary from the latest GitHub Release,
# verifies its checksum, and installs it to $PREFIX/bin (default
# /usr/local/bin, falling back to ~/.local/bin if that isn't writable).
# POSIX sh only -- no bashisms -- since /bin/sh is dash on many systems.
set -e

REPO="rakfortltd/secfoo"
PREFIX="${PREFIX:-/usr/local}"

os_name() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    *)
      echo "error: unsupported OS '$(uname -s)' -- see https://github.com/$REPO/releases for manual download options" >&2
      exit 1
      ;;
  esac
}

arch_name() {
  case "$(uname -m)" in
    arm64|aarch64) echo "arm64" ;;
    x86_64|amd64) echo "x64" ;;
    *)
      echo "error: unsupported architecture '$(uname -m)' -- see https://github.com/$REPO/releases for manual download options" >&2
      exit 1
      ;;
  esac
}

OS=$(os_name)
ARCH=$(arch_name)
ASSET="secfoo-${OS}-${ARCH}"

echo "Detected platform: ${OS}-${ARCH}"

LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
  echo "error: could not determine the latest release tag from the GitHub API" >&2
  exit 1
fi

echo "Latest release: $LATEST_TAG"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

BASE_URL="https://github.com/$REPO/releases/download/$LATEST_TAG"
curl -fsSL -o "$TMP_DIR/$ASSET" "$BASE_URL/$ASSET"
curl -fsSL -o "$TMP_DIR/SHA256SUMS" "$BASE_URL/SHA256SUMS"

echo "Verifying checksum..."
EXPECTED=$(grep " $ASSET\$" "$TMP_DIR/SHA256SUMS" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  echo "error: no checksum entry found for $ASSET in SHA256SUMS" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP_DIR/$ASSET" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$TMP_DIR/$ASSET" | awk '{print $1}')
else
  echo "error: neither sha256sum nor shasum is available to verify the download" >&2
  exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "error: checksum mismatch for $ASSET (expected $EXPECTED, got $ACTUAL) -- aborting install" >&2
  exit 1
fi
echo "Checksum OK."

chmod +x "$TMP_DIR/$ASSET"

INSTALL_DIR="$PREFIX/bin"
if [ ! -w "$INSTALL_DIR" ] 2>/dev/null; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

mv "$TMP_DIR/$ASSET" "$INSTALL_DIR/secfoo"
echo "Installed secfoo $LATEST_TAG to $INSTALL_DIR/secfoo"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Note: $INSTALL_DIR is not on your PATH. Add it, e.g.: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

"$INSTALL_DIR/secfoo" agents || true
