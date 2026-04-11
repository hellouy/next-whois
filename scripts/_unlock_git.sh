#!/bin/sh
LOCK=".git/index.lock"
if [ -f "$LOCK" ]; then
  rm "$LOCK" && echo "Lock removed" || echo "Failed to remove"
else
  echo "No lock file found"
fi
