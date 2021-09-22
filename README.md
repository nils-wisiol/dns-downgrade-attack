# DNS Downgrade attack

Research implementation of a authoritative name server that serves a zone signed with the commonly used ecdsa256 and
the new, not yet widely supported, ed448.
The name server listens on port 5301 for incoming tcp and udp queries.

On port 53, we implemented a "mitm attack" using a reverse proxy on the auth NS, which removes the ecdsa signature
and modifies the content of any TXT record contained in the response.
