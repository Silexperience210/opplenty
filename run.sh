#!/usr/bin/env bash
# opplenty launcher — starts the local UI and opens it in your browser.
set -e
cd "$(dirname "$0")"
URL="http://127.0.0.1:8787"
( sleep 2
  if command -v termux-open-url >/dev/null 2>&1; then termux-open-url "$URL"
  elif command -v xdg-open       >/dev/null 2>&1; then xdg-open "$URL"
  elif command -v open           >/dev/null 2>&1; then open "$URL"
  fi ) &
exec python3 -m opplenty.server
