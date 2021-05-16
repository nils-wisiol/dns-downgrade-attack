# Agile DNSSEC DNS Server

Research implementation of a DNS server that implements agile DNSSEC.

## Design

In the background, we run a knot DNS server that ultimately answers all queries.
Queries are accepted by a sloppy custom Python proxy script, which may filter responses.

## Installation and Startup

To run the DNS server, clone this repository and run it using

```shell
docker-compose up -d
```

### "Agile" DNS Zones

An "agile" DNS Zone that is signed with many different types of ciphers can be added by calling

```shell
docker-compose exec ns /root/bin/addagilezone.sh your.zone.example.com hostname.of.your.ns.com
```

This will add the zone to knot and sign it using many algorithms.
It also displays the DS records that need to be configured in the parent zone to establish the chain of trust.

### Test DNS Zone

To add many zones using *one* signature algorithm each, run

```shell
docker-compose exec ns /root/bin/addtestzones.sh parent.zone.com hostname.of.your.ns.com
```


## Query

Standard query to this server result in the standard answers:

```shell
dig SOA +dnssec @yourns.example.com your.zone.example.com
```

Querying this server setting EDNS Option #14 with a byte array of acceptable algorithms will filter the response's
RRSIGs according to the algorithm in use:

```shell
dig SOA +dnssec @yourns.example.com your.zone.example.com +ednsopt=14:0d05
```

This will only transmit signatures of type `0x0d = 13` (ECDSAP256SHA256) and `0x05 = 5` (RSASHA1).
