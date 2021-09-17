#!/usr/bin/env bash

echo "Adding keys"
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=rsasha1 size=1024
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=rsasha256 size=1024
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=rsasha512 size=1024
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=ecdsap256sha256 size=256
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=ecdsap384sha384 size=384
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=ed25519
keymgr "agile.$ZONE" generate zsk=true ksk=true algorithm=16


echo "Setting up a minimalistic zone for $ZONE"
knotc conf-begin
knotc conf-set zone[agile.$ZONE]
knotc conf-set zone[agile.$ZONE].dnssec-policy default
knotc conf-set zone[agile.$ZONE].dnssec-signing on
knotc conf-commit
knotc zone-begin "agile.$ZONE"
knotc zone-set "agile.$ZONE" @ 0 SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 3600
knotc zone-set "agile.$ZONE" @ 0 NS "1.agile.b.ns.$ZONE."
knotc zone-set "agile.$ZONE" @ 0 A "$A_RECORD"
knotc zone-set "agile.$ZONE" @ 0 TXT "agility"
knotc zone-set "agile.$ZONE" "*" 0 A "$A_RECORD"
knotc zone-set "agile.$ZONE" "*" 0 TXT "agility"
knotc zone-commit "agile.$ZONE"

echo "Reloading zone"
knotc zone-sign "agile.$ZONE"

echo "Add these DS records to the delegating zone:"
keymgr "agile.$ZONE" ds

echo "Add these NS records to the delegating zone:"
echo $ZONE agile 0 NS "1.agile.b.ns.$ZONE"
