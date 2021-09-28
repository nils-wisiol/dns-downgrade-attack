# DNS Downgrade attack

Research implementation of a authoritative name server that serves a zone signed with the commonly used ecdsa256 and
the new, not yet widely supported, ed448.
The name server listens on port 5301 for incoming tcp and udp queries.

On port 53, we implemented a "mitm attack" using a reverse proxy on the auth NS, which removes the ecdsa signature
and modifies the content of any TXT record contained in the response.

## SSL Zertificates

To obtain certificates for test domains via ZeroSSL, set an email address for your new ZeroSSL account

```shell
export EMAIL=myexample.com
```

Access to the mailbox given is (as of today) not required.
Then use acme.sh:

```shell
git submodule init
git submodule update
source .env
export KNOT_SERVER=$IP_NS
export KNOT_KEY=`grep \# acme/keys/acme.key | cut -d' ' -f2`
bash acme.sh/acme.sh --register-account -m $EMAIL
ZONES=$(docker-compose exec ns knotc zone-status | cut -d ' ' -f1 | sed 's/[][]//g' | sort | uniq)
for Z in $(echo $ZONES); do
Z=$(basename $Z .)
echo "+++++++++++++++++++ Applying for certificate for $Z +++++++++++++++++++"
bash acme.sh/acme.sh --issue --dns dns_knot -d $Z -d "*.$Z" --server zerossl --dnssleep 1
done
```

The command can be run again in case it could not complete or certificates are expiring soon.
Certificates that are still good will be skipped.
