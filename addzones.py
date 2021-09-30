import itertools
import json
import logging
import os
import shutil
import subprocess
from typing import List

import dns.dnssec
import dns.name
import dns.rrset
import requests
from tqdm import tqdm

# requirements: dnspython, requests, tqdm

logging.basicConfig(level=logging.WARNING)

ZONE = dns.name.from_text(os.environ.get('ZONE'))
MITM_A_RR = os.environ.get('MITM_A_RR')
A_RR = os.environ.get('A_RR')
TTL = os.environ.get('TTL', 0)
DESEC_TOKEN = os.environ['DESEC_TOKEN']

IN = dns.rdataclass.from_text("IN")
DS = dns.rdatatype.from_text("DS")
DNSKEY = dns.rdatatype.from_text("DNSKEY")
NS = dns.rdatatype.from_text("NS")

ALGORITHMS = [
    dns.dnssec.RSASHA1,
    dns.dnssec.RSASHA256,
    dns.dnssec.RSASHA512,
    dns.dnssec.ECDSAP256SHA256,
    dns.dnssec.ECDSAP384SHA384,
    dns.dnssec.ED25519,
    dns.dnssec.ED448,
]


def run(args, stdin: str = None) -> str:
    logging.debug(f"Running {args}")
    if stdin:
        logging.debug(f"Sending stdin of length {len(stdin)}")
        logging.info(f"stdin: {stdin}")
    stdout = subprocess.run(args, stdout=subprocess.PIPE, text=True, input=stdin).stdout
    logging.info(f"stdout: {stdout}")
    return stdout


def knotc(commands: str) -> str:
    return run(["knotc"], stdin=commands)


def add_algorithm(zone: dns.name.Name, algorithm: dns.dnssec.Algorithm) -> None:
    keysizes = {
        dns.dnssec.RSASHA1: 2048,
        dns.dnssec.RSASHA256: 2048,
        dns.dnssec.RSASHA512: 2048,
        dns.dnssec.ECDSAP256SHA256: 256,
        dns.dnssec.ECDSAP384SHA384: 384,
        dns.dnssec.ED25519: 256,
        dns.dnssec.ED448: 456,
    }
    stdout = run(["keymgr", zone.to_text(), "generate", f"algorithm={algorithm}", f"size={keysizes[algorithm]}", "ksk=true", "zsk=true"])
    keyid = [line for line in stdout.strip().split('\n') if 'warning' not in line][0]
    shutil.copyfile(f"/storage/keys/keys/{keyid}.pem", f"/fixed-keys/{zone.to_text()}-{algorithm}.pem")


def get_ds(zone: dns.name.Name) -> dns.rrset.RRset:
    stdout = run(["keymgr", zone.to_text(), "ds"])
    content = [x.split(' ', 2)[-1] for x in stdout.split('\n') if x]
    logging.debug(content)
    return dns.rrset.from_text_list(zone, TTL, IN, DS, content)


def get_dnskeys(zone: dns.name.Name) -> dns.rrset.RRset:
    stdout = run(["keymgr", zone.to_text(), "dnskey"])
    content = [x.split(' ', 2)[-1] for x in stdout.split('\n') if x]
    logging.debug(content)
    return dns.rrset.from_text_list(zone, TTL, IN, DNSKEY, content)


def delegate(delegatee: dns.name.Name) -> List[dns.rrset.RRset]:
    delegator = delegatee.parent()
    logging.debug(f"Delegating from {delegator} to {delegatee}")
    ds = get_ds(delegatee)
    ns = dns.rrset.from_text(delegatee, TTL, IN, NS, (dns.name.Name(['ns']) + delegator).to_text())
    return [ns, ds]


def add_zone(name: dns.name.Name, a_record: str, ns_a_record: str, sign_with: List[dns.dnssec.Algorithm],
             remove_dnskeys: List[dns.dnssec.Algorithm]):
    fqdn = name.to_text()
    ns = dns.name.Name(['ns'])
    knotc(
        f"""
        conf-begin
            conf-set "zone[{fqdn}]"
            conf-set "zone[{fqdn}].dnssec-signing" off
            conf-set "zone[{fqdn}].acl" "acme"
        conf-commit
        
        zone-begin "{fqdn}"
            zone-set "{fqdn}" @ {TTL} SOA get.desec.io. get.desec.io. 2021014779 86400 86400 2419200 {TTL}
            zone-set "{fqdn}" @ {TTL} NS "{(ns + name).to_text()}"
            zone-set "{fqdn}" ns {TTL} A "{ns_a_record}"
            zone-set "{fqdn}" @ {TTL} A "{a_record}"
            zone-set "{fqdn}" * {TTL} A "{a_record}"
            zone-set "{fqdn}" @ {TTL} TXT "research test zone"
            zone-set "{fqdn}" * {TTL} TXT "research test zone"
        zone-commit "{fqdn}"        
        """
    )

    for algorithm in sign_with:
        add_algorithm(name, algorithm)

    if sign_with:
        knotc(
            f"""
            conf-begin
                conf-set "zone[{fqdn}].dnssec-policy" "nsec1"
                conf-set "zone[{fqdn}].dnssec-signing" on
            conf-commit            
            """
        )

    if remove_dnskeys:
        dnskeys = get_dnskeys(name)
        for dnskey in dnskeys:
            if dnskey.algorithm in remove_dnskeys:
                knotc(
                    f"""
                    zone-begin "{fqdn}"
                        zone-unset "{fqdn}" @ DNSKEY {dnskey}
                    zone-commit "{fqdn}"               
                    """
                )


zones = [
    (
        algos, remove_dnskeys,
        dns.name.from_text(
            "-".join(
                [f"ds{a}" for a in sorted(algos)] +
                [f"dnskey{int(a)}" for a in sorted(set(algos) - set(remove_dnskeys))]
            ),
            origin=ZONE
        ),
    )
    for algos in itertools.chain(itertools.combinations(ALGORITHMS, 1), itertools.combinations(ALGORITHMS, 2))
    for remove_dnskeys in [[a for i, a in enumerate(algos) if v[i]] for v in itertools.product([True, False], repeat=len(algos))]
]

for algorithms, remove_dnskeys, name in tqdm(zones):
    add_zone(
        name=name,
        a_record=A_RR,
        ns_a_record=MITM_A_RR,
        sign_with=algorithms,
        remove_dnskeys=remove_dnskeys,
    )

for a in tqdm(ALGORITHMS):
    add_zone(
        name=dns.name.from_text(f"broken{a}", origin=ZONE),
        a_record=A_RR,
        ns_a_record=MITM_A_RR,
        sign_with=[a],
        remove_dnskeys=[a],
    )

delegations = [rrset for _, _, zone in zones for rrset in delegate(zone)]
data = json.dumps([
        {
            'subname': dns.name.Name(rrset.name[:1]).to_text(), 'ttl': 60,
            'type': dns.rdatatype.to_text(rrset.rdtype), 'records': [rr.to_text() for rr in rrset],
        }
        for rrset in delegations
    ], indent=4)
requests.patch(
    url=f"https://desec.io/api/v1/domains/{ZONE.to_text().rstrip('.')}/rrsets/",
    headers={
        'Authorization': f'Token {DESEC_TOKEN}',
        'Content-Type': 'application/json',
    },
    data=data
)

