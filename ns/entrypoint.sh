#!/usr/bin/env bash
set -e
set -o xtrace

if [[ ! -d /storage/confdb ]]; then
  # First time booting: setup initial configuration
  knotd -C /storage/confdb &
  PID=$!
  knotc conf-init
  knotc <<EOF
conf-begin
conf-set server.listen 0.0.0.0@53
conf-commit
EOF
  kill $PID
fi

exec knotd -C /storage/confdb
