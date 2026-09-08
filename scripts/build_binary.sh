#!/usr/bin/env bash
# Builds a standalone secfoo binary for the current platform/arch into
# dist/binary/. Used both locally and by .github/workflows/release.yml --
# PyInstaller cannot cross-compile, so this must run once per target OS.
set -euo pipefail
cd "$(dirname "$0")/.."

pyinstaller packaging/secfoo.spec \
  --distpath dist/binary \
  --workpath build/pyinstaller \
  --noconfirm

echo "Built: dist/binary/secfoo"
