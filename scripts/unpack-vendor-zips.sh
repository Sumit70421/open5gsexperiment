#!/usr/bin/env bash
#
# The vendored dependency source (~250MB uncompressed) is shipped as three
# separate zip files (upload size limits), split alongside the small repo
# zip. Run this after downloading all four, with all four .zip files in the
# same directory as this script (or pass that directory as $1), to merge
# them back into vendor/ so install.sh's fetch_source() picks them up.
#
# Usage:
#   ./scripts/unpack-vendor-zips.sh [dir-containing-the-zips]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ZIP_DIR="${1:-$REPO_DIR}"

shopt -s nullglob
found=0
for z in "$ZIP_DIR"/open5gsexperiment-*vendor*.zip; do
  echo "==> Extracting $(basename "$z")"
  unzip -o -q "$z" -d "$REPO_DIR"
  found=1
done
shopt -u nullglob

if [[ $found -eq 0 ]]; then
  echo "No open5gsexperiment-*vendor*.zip files found in $ZIP_DIR" >&2
  exit 1
fi

echo "==> Done. vendor/ now contains:"
ls "$REPO_DIR/vendor"
