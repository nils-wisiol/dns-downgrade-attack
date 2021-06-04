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
docker-compose exec ns /root/bin/addtestzones.sh parent.zone.com 1.2.3.4 2.3.4.5
```

where 1.2.3.4 and 2.3.4.5 are the IP addresses of the exactly two authoritative name servers.

Keys will be stored in the `keys/` directory. Any already present keys will be imported and used.
Naming schema is `$ZONE.key.pem`.

To synchronize keys, rsync can be used. Move keys from local to server:

```shell
rsync -rtP keys/ ns1.example.com:adnssec/keys/
```

Move from server to local:

```shell
rsync -rtP ns1.example.com:adnssec/keys/ keys/
```

The test zones created use algorithms according to the recommendations of RFC 8624.
All algorithms that are "MUST" or "RECOMMENDED" for validation are included.
The key sizes for RSA-based algorithms vary, the key sizes for elliptic curve methods are fixed.
All zones used a common zone key, i.e. a hash of the key is included as `DS` record in the parent zone and the key is
used to sign record sets.

| Number | Mnemonics          | DNSSEC Signing  | DNSSEC Validation | Used Key Sizes
| ------ | ------------------ | --------------- | ----------------- | -------------------
| 1      | RSAMD5             | MUST NOT        | MUST NOT          | -
| 3      | DSA                | MUST NOT        | MUST NOT          | -
| 5      | RSASHA1            | NOT RECOMMENDED | MUST              | 1024 1871 2048 4096
| 6      | DSA-NSEC3-SHA1     | MUST NOT        | MUST NOT          | -
| 7      | RSASHA1-NSEC3-SHA1 | NOT RECOMMENDED | MUST              | 1024 1871 2048 4096
| 8      | RSASHA256          | MUST            | MUST              | 1024 1871 2048 4096
| 10     | RSASHA512          | NOT RECOMMENDED | MUST              | 1024 1871 2048 4096
| 12     | ECC-GOST           | MUST NOT        | MAY               | -
| 13     | ECDSAP256SHA256    | MUST            | MUST              | 256
| 14     | ECDSAP384SHA384    | MAY             | RECOMMENDED       | 384
| 15     | ED25519            | RECOMMENDED     | RECOMMENDED       | 256
| 16     | ED448              | MAY             | RECOMMENDED       | 456

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

## Traffic Capture

This repo contains a systemd service that captures all port 53 traffic on eth0.
It can be installed and enabled using

```shell
cp -rav tcplogger/* /
systemctl enable tcplogger
```

Captured traffic will be put in `/var/log/tcplogger` and logrotated.
