#!/usr/bin/env bash

ZONE="$1"
NS="$2"

if [ -z "$ZONE" ]; then
  echo "Provide a zone name as first argument."
  exit 1
fi

echo "Adding keys"
keymgr "$ZONE" generate zsk=true ksk=true algorithm=rsasha1 size=1024
keymgr "$ZONE" generate zsk=true ksk=true algorithm=rsasha256 size=1024
keymgr "$ZONE" generate zsk=true ksk=true algorithm=rsasha512 size=1024
keymgr "$ZONE" generate zsk=true ksk=true algorithm=ecdsap256sha256 size=256
keymgr "$ZONE" generate zsk=true ksk=true algorithm=ecdsap384sha384 size=384
keymgr "$ZONE" generate zsk=true ksk=true algorithm=ed25519


echo "Setting up a minimalistic zone for $ZONE"
knotc conf-begin
knotc conf-set zone[$ZONE]
knotc conf-set zone[$ZONE].dnssec-policy default
knotc conf-set zone[$ZONE].dnssec-signing on
knotc conf-commit
knotc zone-begin "$ZONE"
knotc zone-set "$ZONE" @ 7200 SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 3600
knotc zone-set "$ZONE" @ 3600 NS "$NS."
knotc zone-set "$ZONE" @ 3600 A 127.0.0.1
knotc zone-set "$ZONE" @ 3600 AAAA ::1
knotc zone-set "$ZONE" @ 3600 TXT "agility"
knotc zone-commit "$ZONE"

echo "Reloading zone"
knotc zone-sign "$ZONE"

echo "Add these DS records to the delegating zone:"
keymgr "$ZONE" ds
