#!/usr/bin/env bash
set -e

DOMAIN=$1
NS=$2

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: ./addtestzones.sh [parent domain]"
  exit 1
fi

create_zone() {
  ZONE=$1
  ALGORITHM=$2
  KEYSIZE=$3
  if [[ -n $ALGORITHM ]]; then
    echo "Creating secure zone $ZONE"
    keymgr "$ZONE" generate algorithm="${ALGORITHM}" size="$KEYSIZE" ksk=true zsk=true
    knotc conf-begin
    knotc conf-set zone[$ZONE]
    knotc conf-set zone[$ZONE].dnssec-policy default
    knotc conf-set zone[$ZONE].dnssec-signing on
    knotc conf-commit
  else
    echo "Creating insecure zone $ZONE"
    knotc conf-begin
    knotc conf-set zone[$ZONE]
    knotc conf-set zone[$ZONE].dnssec-signing off
    knotc conf-commit
  fi
  knotc zone-begin "$ZONE"
  knotc zone-set "$ZONE" @ 7200 SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 3600
  knotc zone-set "$ZONE" @ 3600 NS "$NS."
  knotc zone-set "$ZONE" @ 3600 A 127.0.0.1
  knotc zone-set "$ZONE" @ 3600 AAAA ::1
  knotc zone-set "$ZONE" @ 3600 TXT "research test zone"
  knotc zone-commit "$ZONE"
}

delegate() {
  SUBNAME=$1
  PARENT=$2
  echo "Adding NS and DS for $SUBNAME.$PARENT to $PARENT"
  knotc zone-begin "$PARENT"
  knotc zone-set "$PARENT" "$SUBNAME" 3600 NS "$NS."
  keymgr "$SUBNAME.$PARENT" ds | cut -d ' ' -f 3- | while read -r DS
  do
    echo knotc zone-set "$PARENT" "$SUBNAME" 3600 DS $DS
    knotc zone-set "$PARENT" "$SUBNAME" 3600 DS $DS
  done
  knotc zone-commit "$PARENT"
}

delegate_manually() {
  ZONE=$1
  echo "FURTHER ACTION REQUIRED: Add DS records for parent of $ZONE:"
  echo "@@@@"
  keymgr "$ZONE." ds
  echo "@@@@"
}

created_signedok_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  SUBNAME="${ALGORITHM}-${KEYSIZE}-signedok"
  ZONE="${SUBNAME}.${DOMAIN}"
  create_zone "$ZONE" "$ALGORITHM" "$KEYSIZE"
  delegate "$SUBNAME" "$DOMAIN"
}

created_signedbrokennods_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  ZONE="${ALGORITHM}-${KEYSIZE}-signedbrokennods.${DOMAIN}"
  create_zone "$ZONE" "$ALGORITHM" "$KEYSIZE"
}

created_unsigned_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  ZONE="unsigned.${DOMAIN}"
  create_zone "$ZONE"
}

keysizes() {
  case $1 in
  rsasha*)
    echo 1024 2048 4096
    ;;
  ecdsap256*)
    echo 256
    ;;
  ecdsap384*)
    echo 384
    ;;
  ed25519)
    echo 256
    ;;
  esac
}

echo "Creating test zone parent"
create_zone "${DOMAIN}" "rsasha256" "2048"
delegate_manually "$DOMAIN"

for ALGORITHM in rsasha1 rsasha256 rsasha512 ecdsap256sha256 ecdsap384sha384 ed25519; do
  KEYSIZES=$(keysizes $ALGORITHM)
  for KEYSIZE in $KEYSIZES; do
    created_signedok_zone "$ALGORITHM" "$KEYSIZE" "$DOMAIN"
    created_signedbrokennods_zone "$ALGORITHM" "$KEYSIZE" "$DOMAIN"
  done
done
created_unsigned_zone "$ALGORITHM" "$KEYSIZE" "$DOMAIN"

echo "finished successfully"
