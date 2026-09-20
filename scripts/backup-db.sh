#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$DIR/data/db.json"
DEST_DIR="$DIR/data/backups"
mkdir -p "$DEST_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
if [ -f "$SRC" ]; then
  cp "$SRC" "$DEST_DIR/db-$TS.json"
  echo "Backup: $DEST_DIR/db-$TS.json"
  ls -1t "$DEST_DIR"/db-*.json 2>/dev/null | tail -n +15 | xargs -r rm --
else
  echo "No db.json found"
  exit 1
fi
