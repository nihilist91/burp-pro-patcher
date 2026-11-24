#!/usr/bin/env bash
# Rebuild every patch from a pristine jar. Run from the repo root after fetch.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./versions.env
JAR=burpsuite_pro.jar

PY=$(command -v py || command -v python3 || command -v python || true)
[ -n "$PY" ] || { echo "no python interpreter found"; exit 1; }

[ -f "$JAR.orig" ] || { echo "no $JAR.orig - run ./fetch.sh first"; exit 1; }
cp -p "$JAR.orig" "$JAR"
rm -f "$JAR.patchstate.json" tmp*.jar

"$PY" patch/patch_method.py --input "$JAR" --target burp/Zhxf#Zr --expect "$TARGET_SHA256" --force --apply
"$PY" patch/patch_method.py --input "$JAR" --target burp/Zn15#Zl --force --apply
"$PY" patch/patch_code.py   --input "$JAR" --target 'burp/Ztk8#Ze(Ljava/lang/String;)' --code b1 --stack 0 --force --apply
"$PY" patch/patch_licence.py --input "$JAR" --force --apply
"$PY" verify/verify_burp.py --input "$JAR"
echo "OK: rebuilt. launch with: java -noverify -jar $JAR"
