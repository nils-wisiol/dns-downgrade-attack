import logging
from typing import List, Set

import dns.query
import dns.message
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ns = socket.gethostbyname('ns')

MC = 0x4000  # our made-up edns flag for "modern cryptography"


def indent(s, l=4):
    return " " * l + s.replace("\n", "\n" + " " * l)


def filter_signatures(answer: List[dns.rrset.RRset], algs: Set[int] = None):
    algs = algs or {15}

    filtered_answer = []
    for rrset in answer:
        rrset: dns.rrset.RRset = rrset
        if rrset.rdtype == dns.rdatatype.RdataType.RRSIG:
            filtered_rrset: dns.rrset.RRset = rrset.copy()
            for rr in rrset.items:
                if rr.algorithm not in algs:
                    filtered_rrset.remove(rr)
            filtered_answer.append(filtered_rrset)
            logger.info(f"Filtered {len(rrset) - len(filtered_rrset)} signatures from {dns.rdatatype.to_text(rrset.covers)} {rrset.name}")
        else:
            filtered_answer.append(rrset)
    return filtered_answer


server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('0.0.0.0', 5300))
logger.info("Ready to accept queries!")

while True:
    message, (host, port) = server_socket.recvfrom(1024)
    logger.info("accepted packet")
    m = dns.message.from_wire(message)
    if m.opcode() != dns.opcode.Opcode.QUERY:
        logger.warning(f"Message from {host}:{port} wasn't a query: {dns.opcode.to_text(m.opcode())}")
        continue
    q = m
    logger.info(f"Query {q.id} from {host}:{port}")
    logger.info(indent(q.to_text()))
    logger.info(f"Forwarding query {q.id} from {host}:{port} ...")
    a = dns.query.udp(q, where=ns)
    if q.ednsflags & MC != 0:
        logger.info(f"Filtering for 'modern ciphers' (ED25519)")
        a.answer = filter_signatures(a.answer)
    logger.info(f"Forwarding answer {q.id} for {host}:{port} ...")
    logger.info(indent(a.to_text()))
    server_socket.sendto(a.to_wire(), (host, port))
