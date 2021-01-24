#!/usr/bin/env bash

ZONE="$1"

if [ -z "$ZONE" ]; then
  echo "Provide a zone name as first argument."
  exit 1
fi

echo "Setting up a minimalistic zone for $ZONE"

cat << EOF | docker-compose exec -T ns knotc
conf-begin
conf-set zone[$ZONE]
conf-set zone[$ZONE].dnssec-policy default
conf-set zone[$ZONE].dnssec-signing on
conf-commit
zone-begin $ZONE
zone-set $ZONE @ 7200 SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 3600
zone-set $ZONE @ 3600 A 127.0.0.1
zone-set $ZONE @ 3600 AAAA ::1
zone-set $ZONE @ 3600 TXT "agility"
zone-commit $ZONE
EOF

echo "Adding keys"
docker-compose exec ns keymgr $ZONE. generate zsk=true ksk=true algorithm=rsasha1 size=1024
# save some space otherwise full answers won't fit into UDP packets
#docker-compose exec ns keymgr $ZONE. generate zsk=true ksk=true algorithm=rsasha256 size=1024
#docker-compose exec ns keymgr $ZONE. generate zsk=true ksk=true algorithm=rsasha512 size=1024
docker-compose exec ns keymgr $ZONE. generate zsk=true ksk=true algorithm=ecdsap256sha256 size=256
docker-compose exec ns keymgr $ZONE. generate zsk=true ksk=true algorithm=ecdsap384sha384 size=384
docker-compose exec ns keymgr $ZONE. generate zsk=true ksk=true algorithm=ed25519

echo "Reloading zone"
docker-compose exec ns knotc zone-sign $ZONE

echo "Add these DS records to the delegating zone:"
docker-compose exec ns keymgr $ZONE. ds
