#!/usr/bin/env bash
# FCK MULTI TOOL - lancement (Linux / macOS)
cd "$(dirname "$0")"

( xdg-open "https://github.com/cameleonnbss" >/dev/null 2>&1 \
  || open "https://github.com/cameleonnbss" >/dev/null 2>&1 \
  || start "https://github.com/cameleonnbss" >/dev/null 2>&1 ) &

PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

exec $PY main.py "$@"
