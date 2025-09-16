#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/var/www/api/abstract_logins"

echo "== Duplicate blueprint names =="
grep -R --line-number "get_bp(" "$APP_DIR" \
  | sed -E "s/.*get_bp\(([^)]*)\).*/\1/" \
  | sed -E "s/['\"]([^'\"]+)['\"].*/\1/" \
  | sort | uniq -cd || true

echo
echo "== Any functions literally named 'decorator' (bad) =="
grep -R --line-number "def decorator" "$APP_DIR" || true

echo
echo "== Any wrappers missing functools.wraps =="
grep -R --line-number "def wrapper" "$APP_DIR" | while read -r f; do
  file="${f%%:*}"
  line="${f##*:}"
  # Show the previous 3 lines to see if @wraps is present
  nl -ba "$file" | sed -n "$((line-3)),$((line+0))p" | grep -q "@wraps" || echo "No @wraps near: $f"
done
