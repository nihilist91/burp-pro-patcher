#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
. ./versions.env
OUT=burpsuite_pro.jar
[ -f "$OUT" ] && { echo "$OUT exists"; exit 0; }
curl -L --compressed -A "Mozilla/5.0" \
  -e "https://portswigger.net/burp/releases/professional-community-${TARGET_VERSION//./-}" \
  -o "$OUT" "https://portswigger.net/burp/releases/download?product=desktop&type=Jar&version=${TARGET_VERSION}"
if command -v sha256sum >/dev/null 2>&1; then
  GOT=$(sha256sum "$OUT" | cut -d' ' -f1)
else
  GOT=$(shasum -a 256 "$OUT" | cut -d' ' -f1)
fi
[ "$GOT" = "$TARGET_SHA256" ] || { echo "hash mismatch: $GOT"; rm -f "$OUT"; exit 1; }
cp -p "$OUT" "$OUT.orig"
echo "OK: $OUT verified"
