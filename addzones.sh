#!/usr/bin/env bash

#set -e
#set -o xtrace

TTL=0
ORIGIN=$ZONE
NS=ns.$ZONE

add_algorithm() {
  ZONE=$1
  ALGORITHM=$2
  KEYSIZE=$3
  KEYFILE=/fixed-keys/$ZONE-$ALGORITHM.key.pem
  if [[ ! -f $KEYFILE ]]; then
    KEYID=$(keymgr "$ZONE" generate algorithm="${ALGORITHM}" size="$KEYSIZE" ksk=true zsk=true | grep -v warning)
    cp "/storage/keys/keys/$KEYID.pem" "$KEYFILE"
  else
    keymgr "$ZONE" import-pem "$KEYFILE" algorithm="${ALGORITHM}" size="$KEYSIZE" ksk=true zsk=true
  fi
}

create_zone() {
  ZONE=$1
  ALGORITHM=$2
  KEYSIZE=$3

  knotc <<EOF
  conf-begin
    conf-set "zone[$ZONE]"
    conf-set "zone[$ZONE].dnssec-signing" off
  conf-commit

  zone-begin "$ZONE"
    zone-set "$ZONE" @ $TTL SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 $TTL
    zone-set "$ZONE" @ $TTL NS "ns.$ZONE."
    zone-set "$ZONE" ns $TTL A "$IP_MITM"
    zone-set "$ZONE" @ $TTL TXT "research test zone"
    zone-set "$ZONE" unsign $TTL TXT "research test zone"
  zone-commit "$ZONE"
EOF

  echo "Creating secure zone $ZONE"

  # add requested algorithm
  add_algorithm $ZONE $ALGORITHM $KEYSIZE

  # add algorithm 16 (ed448)
  add_algorithm $ZONE 16 456

  knotc <<EOF
  conf-begin
    conf-set "zone[$ZONE].dnssec-policy" "nsec1"
    conf-set "zone[$ZONE].dnssec-signing" on
  conf-commit
EOF
}

delegate_manually() {
  SUBNAME=$1
  PARENT=$2
  echo "FURTHER ACTION REQUIRED: Add DS records for parent of $ZONE:"
  echo zone-begin "$PARENT"
  echo zone-set "$PARENT" "$SUBNAME" $TTL NS "$NS."
  keymgr "$SUBNAME.$PARENT" ds | cut -d ' ' -f 3- | while read -r DS
  do
    echo zone-set "$PARENT" "$SUBNAME" $TTL DS $DS
  done
}

create_zone "rsasha256.${ORIGIN}" "rsasha256" "2048"
create_zone "ecdsap256sha256.${ORIGIN}" "ecdsap256sha256" "256"

delegate_manually "rsasha256.${ORIGIN}"
delegate_manually "ecdsap256sha256.${ORIGIN}"
