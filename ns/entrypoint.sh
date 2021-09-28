#!/usr/bin/env bash
set -e
set -o xtrace

if [[ ! -f /etc/knot/acme/acme.key ]]; then
  keymgr tsig generate -t acme_key hmac-sha512 > /etc/knot/acme/acme.key
fi

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
conf-set include /etc/knot/acme/acme.key
conf-set acl[acme]
conf-set acl[acme].address 0.0.0.0/0
conf-set acl[acme].action update
conf-set acl[acme].key acme_key
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
