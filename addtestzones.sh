#!/usr/bin/env bash
set -e
set -o xtrace

ROOT=$ZONE
LABELS=$1
TTL=0

if [[ -z "$ROOT" ]]; then
  echo "Usage: ./addtestzones.sh [parent domain] [A record] [num labels]"
  exit 1
fi

create_zone() {
  ZONE=$1
  ALGORITHM=$2
  KEYSIZE=$3
  NSEC=$4

  knotc <<EOF
  conf-begin
    conf-set "zone[$ZONE]"
    conf-set "zone[$ZONE].dnssec-signing" off
  conf-commit

  zone-begin "$ZONE"
    zone-set "$ZONE" @ $TTL SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 $TTL
    zone-set "$ZONE" @ $TTL NS "1.a.ns.$ZONE."
    zone-set "$ZONE" @ $TTL NS "2.a.ns.$ZONE."
    zone-set "$ZONE" 1.a.ns $TTL A "$IP_NS_A_1"
    zone-set "$ZONE" 2.a.ns $TTL A "$IP_NS_A_2"
    zone-set "$ZONE" 1.b.ns $TTL A "$IP_NS_B_1"
    zone-set "$ZONE" 1.agile.b.ns $TTL A "$IP_NS_B_AGILE_1"
    zone-set "$ZONE" @ $TTL A "$A_RECORD"
    zone-set "$ZONE" @ $TTL TXT "research test zone"
    zone-set "$ZONE" '*' $TTL A "$A_RECORD"
    zone-set "$ZONE" '*' $TTL TXT "research test zone"
  zone-commit "$ZONE"
EOF

  if [[ -n $ALGORITHM ]]; then
    echo "Creating secure zone $ZONE"
    KEYFILE=/fixed-keys/$ZONE.key.pem
    ALGORITHM1=$ALGORITHM
    if [[ $ALGORITHM == "ed448" ]]; then
      # using 16 instead of ed448 (https://gitlab.nic.cz/knot/knot-dns/-/issues/739)
      ALGORITHM1=16
    fi
    if [[ ! -f $KEYFILE ]]; then
      KEYID=$(keymgr "$ZONE" generate algorithm="${ALGORITHM1}" size="$KEYSIZE" ksk=true zsk=true)
      cp "/storage/keys/keys/$KEYID.pem" "$KEYFILE"
    else
      keymgr "$ZONE" import-pem "$KEYFILE" algorithm="${ALGORITHM1}" size="$KEYSIZE" ksk=true zsk=true
    fi
    keymgr "$ZONE" nsec3-salt
    knotc <<EOF
    conf-begin
      conf-set "zone[$ZONE].dnssec-policy" "nsec$NSEC"
      conf-set "zone[$ZONE].dnssec-signing" on
    conf-commit
EOF
  else
    echo "Creating insecure zone $ZONE"
  fi
}

delegate() {
  SUBNAME=$1
  PARENT=$2
  SECURE=$3
  echo "Adding NS and DS for $SUBNAME.$PARENT to $PARENT"
  knotc <<EOF
  zone-begin "$PARENT"
  zone-set "$PARENT" "$SUBNAME" $TTL NS "1.a.ns.$PARENT."
  zone-set "$PARENT" "$SUBNAME" $TTL NS "2.a.ns.$PARENT."
EOF
  if [[ -n "$SECURE" ]]; then
    keymgr "$SUBNAME.$PARENT" ds | cut -d ' ' -f 3- | while read -r DS
    do
      knotc zone-set "$PARENT" "$SUBNAME" $TTL DS $DS
    done
  fi
  knotc zone-commit "$PARENT"
}

delegate_manually() {
  SUBNAME=$1
  PARENT=$2
  SECURE=$3
  echo "FURTHER ACTION REQUIRED: Add DS records for parent of $ZONE:"
  echo zone-begin "$PARENT"
  echo zone-set "$PARENT" "$SUBNAME" $TTL NS "$NS."
  if [[ -n "$SECURE" ]]; then
    keymgr "$SUBNAME.$PARENT" ds | cut -d ' ' -f 3- | while read -r DS
    do
      echo zone-set "$PARENT" "$SUBNAME" $TTL DS $DS
    done
  fi
  echo zone-commit "$PARENT"
}

create_label_zone() {
  DOMAIN=$1
  LABEL=$2
  create_zone "$LABEL.$DOMAIN" "rsasha256" 2048 1
  delegate "$LABEL" "$DOMAIN" securely
}

create_signedok_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  NSEC=$4
  SUBNAME="${ALGORITHM}-${KEYSIZE}-${NSEC}-signedok"
  ZONE="${SUBNAME}.${DOMAIN}"
  create_zone "$ZONE" "$ALGORITHM" "$KEYSIZE" "$NSEC"
  delegate "$SUBNAME" "$DOMAIN" securely
}

create_signedbrokennods_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  SUBNAME="${ALGORITHM}-${KEYSIZE}-${NSEC}-signedbrokennods"
  ZONE="${SUBNAME}.${DOMAIN}"
  create_zone "$ZONE" "$ALGORITHM" "$KEYSIZE" "$NSEC"
  delegate "$SUBNAME" "$DOMAIN"
}

create_signedbrokenwrongds_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  SUBNAME="${ALGORITHM}-${KEYSIZE}-${NSEC}-signedbrokenwrongds"
  ZONE="${SUBNAME}.${DOMAIN}"
  create_zone "$ZONE" "$ALGORITHM" "$KEYSIZE" "$NSEC"
  delegate "$SUBNAME" "$DOMAIN"
  # delegate some unrelated key
  knotc <<EOF
  zone-begin "$DOMAIN"
    zone-set "$DOMAIN" "$SUBNAME" $TTL DS "25222 8 2 9740bf5bcc618af66c764d51522e5fd3913a187d09d89d03de079eef43152990"
    zone-set "$DOMAIN" "$SUBNAME" $TTL DS "25222 8 4 d9a75c1579df7939b3c2e5417c08d0c91e017c7912f86b253a9407f561d8e67d732f8f5c051a4d416b22c598453b281f"
  zone-commit "$DOMAIN"
EOF
}

create_unsigned_zone() {
  ALGORITHM=$1
  KEYSIZE=$2
  DOMAIN=$3
  ZONE="unsigned.${DOMAIN}"
  create_zone "$ZONE"
  delegate "unsigned" "$DOMAIN"
}

keysizes() {
  # for allowed key sizes, check https://gitlab.nic.cz/knot/knot-dns/-/blob/master/src/libdnssec/key/algorithm.c#L33
  case $1 in
  rsasha*)
    echo 1024 1871 2048 4096  # All 1024 <= x <= 4096 are allowed by knot
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
  ed448)
    echo 456
    ;;
  esac
}

echo "Creating test zone parent"
create_zone "${ROOT}" "rsasha256" "2048" 1
delegate_manually "$ROOT"

for ((LABEL_IDX=-1; LABEL_IDX<LABELS; LABEL_IDX++)); do
  if [[ $LABEL_IDX -eq -1 ]]; then
    LABEL=
  else
    LABEL=$(printf %x "$LABEL_IDX")
    create_label_zone "$ROOT" "$LABEL"
    LABEL=$LABEL.
  fi
  for ALGORITHM in rsasha1 rsasha1nsec3sha1 rsasha256 rsasha512 ecdsap256sha256 ecdsap384sha384 ed25519 ed448; do
    KEYSIZES=$(keysizes $ALGORITHM)
    for KEYSIZE in $KEYSIZES; do
      for NSEC in 1 3; do
        echo "DOMAIN: $LABEL$ROOT"
        create_signedok_zone "$ALGORITHM" "$KEYSIZE" "$LABEL$ROOT" "$NSEC"
        create_signedbrokennods_zone "$ALGORITHM" "$KEYSIZE" "$LABEL$ROOT" "$NSEC"
        create_signedbrokenwrongds_zone "$ALGORITHM" "$KEYSIZE" "$LABEL$ROOT" "$NSEC"
      done
    done
  done
done
create_unsigned_zone "$ALGORITHM" "$KEYSIZE" "$ROOT"

echo "finished successfully"
