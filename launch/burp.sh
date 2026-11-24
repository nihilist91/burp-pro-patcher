#!/usr/bin/env bash
cd "$(dirname "$0")/.."
exec java -noverify -Xmx4g -jar burpsuite_pro.jar "$@"
