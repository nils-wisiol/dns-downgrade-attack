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
conf-set policy[nsec1]
conf-set policy[nsec1].manual true
conf-set policy[nsec1].nsec3 false
conf-set policy[nsec3]
conf-set policy[nsec3].manual true
conf-set policy[nsec3].nsec3 true
conf-set policy[nsec3].nsec3-iterations 1
conf-set policy[nsec3].nsec3-salt-length 0
conf-commit
EOF
  knotd -C /storage/confdb &
  PID=$!
  sleep 2
  knotc conf-read
  kill $PID
fi

rm -f /rundir/knot.{pid,sock}
exec knotd -C /storage/confdb
