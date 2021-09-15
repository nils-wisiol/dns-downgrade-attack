#!/usr/bin/env bash

source .env

DOMAIN=$1
export TIMEFORMAT='%3R'

#dig @$IP_NS1 $DOMAIN || (echo "Error"; exit 1)

echo SERVER,PROTO,SECURITY,TIME_1000Q_S

for SERVER in $IP_NS1 $IP_AGILE_NS1; do
  for PROTO in +tcp +notcp; do
    for SECURITY in +dnssec +nodnssec; do
      TIME=$(time (for I in {1..1000}; do dig @$SERVER $DOMAIN $SECURITY $PROTO > /dev/null; done) 2>&1)
      echo $SERVER,$PROTO,$SECURITY,$TIME
    done
  done
done
