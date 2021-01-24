import logging
import os
import socket
import socketserver
import struct
import traceback
import threading
from typing import List, Set, Optional

import dns.message
import dns.query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ns = socket.gethostbyname(os.environ.get('ADNSSEC_UPSTREAM_HOST', 'ns'))

AC = 0x4000  # our made-up edns flag for "agile cryptography"


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


def digest(message: bytes, host: str, port: int) -> Optional[bytes]:
    logger.info("accepted packet")
    m = dns.message.from_wire(message)
    if m.opcode() != dns.opcode.Opcode.QUERY:
        logger.warning(f"Message from {host}:{port} wasn't a query: {dns.opcode.to_text(m.opcode())}")
        return
    q = m
    logger.info(f"Query {q.id} from {host}:{port}")
    logger.info(indent(q.to_text()))
    logger.info(f"Forwarding query {q.id} from {host}:{port} ...")
    a = dns.query.udp(q, where=ns, port=int(os.environ.get('ADNSSEC_UPSTREAM_PORT', 53)), timeout=1)

    accept_algorithm = {}  # all
    for opt in next(iter(q.opt.items)).options:
        if opt.otype == 14:  # AC OPT option
            accept_algorithm = {b for b in opt.data}
    if accept_algorithm:
        logger.info(f"Filtering for signatures to match {accept_algorithm}")
        a.answer = filter_signatures(a.answer, accept_algorithm)

    logger.info(f"Forwarding answer {q.id} for {host}:{port} ...")
    logger.info(indent(a.to_text()))
    return a.to_wire()


class Handler(socketserver.BaseRequestHandler):
    SERVER = None

    @classmethod
    def serve(cls):
        logger.info(f"starting {cls.SERVER} ...")
        with cls.SERVER((HOST, PORT), cls) as server:
            server.serve_forever()

    def digest(self, data):
        try:
            return digest(data, self.client_address[0], self.client_address[1])
        except dns.exception.Timeout:
            logger.error(traceback.format_exc())


class UDPHandler(Handler):
    SERVER = socketserver.UDPServer

    def handle(self):
        data = self.request[0]
        response = self.digest(data)
        if response is not None:
            self.request[1].sendto(response, self.client_address)


class TCPHandler(Handler):
    SERVER = socketserver.TCPServer

    def handle(self):
        # self.request is the TCP socket connected to the client
        length = struct.unpack('!h', self.request.recv(2))[0]
        data = self.request.recv(length)
        response = self.digest(data)
        if response is not None:
            length = struct.pack('!h', len(response))
            self.request.sendall(length + response)


HOST, PORT = "0.0.0.0", 5300

if __name__ == "__main__":
    threading.Thread(target=UDPHandler.serve).start()
    threading.Thread(target=TCPHandler.serve).start()
