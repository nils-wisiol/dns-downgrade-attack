import logging
import multiprocessing
import os
import socket
import socketserver
import struct
import traceback
from typing import Set, Optional

import dns.message
import dns.query
import dns.rrset

IN = dns.rdataclass.from_text("IN")
TXT = dns.rdatatype.from_text("TXT")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_ns_addr = socket.gethostbyname(os.environ.get('AUTH_NS_HOST', 'ns'))
auth_ns_port = int(os.environ.get('AUTH_NS_PORT', 53))


def indent(s, l=4):
    return " " * l + s.replace("\n", "\n" + " " * l)


def filter_signatures(a: dns.message.QueryMessage, algs: Set[int] = None):
    algs = algs or {15}
    if a.question[0].name[0] == b'unsign':
        algs = {}

    def filter_section(section):
        filtered_section = []
        for rrset in section:
            rrset: dns.rrset.RRset = rrset
            if rrset.rdtype == dns.rdatatype.RdataType.RRSIG:
                filtered_rrset: dns.rrset.RRset = rrset.copy()
                for rr in rrset.items:
                    if rr.algorithm not in algs:
                        filtered_rrset.remove(rr)
                filtered_section.append(filtered_rrset)
                logger.info(f"Filtered {len(rrset) - len(filtered_rrset)} signatures from {dns.rdatatype.to_text(rrset.covers)} {rrset.name}")
            else:
                if rrset.rdtype == dns.rdatatype.RdataType.TXT:
                    filtered_section.append(dns.rrset.from_text_list(rrset.name, rrset.ttl, IN, TXT, ['evil']))
                filtered_section.append(rrset)
        return filtered_section

    a.answer = filter_section(a.answer)
    a.authority = filter_section(a.authority)
    a.additional = filter_section(a.additional)


def digest(message: bytes, host: str, port: int) -> Optional[bytes]:
    logger.info(f"accepted packet at pid {os.getpid()}")
    m = dns.message.from_wire(message)
    if m.opcode() != dns.opcode.Opcode.QUERY:
        logger.warning(f"Message from {host}:{port} wasn't a query: {dns.opcode.to_text(m.opcode())}")
        return
    q = m
    logger.info(f"Query {q.id} from {host}:{port}")
    logger.info(indent(q.to_text()))
    logger.info(f"Forwarding query {q.id} from {host}:{port} ...")
    a = dns.query.tcp(q, where=auth_ns_addr, port=auth_ns_port, timeout=1)
    logger.info(f"Received upstream answer for {q.id}, {host}:{port} ...")
    logger.info(indent(a.to_text()))

    accept_algorithm = {15, 16}  # ed25519, ed448

    if BE_EVIL and accept_algorithm:
        logger.info(f"Filtering for signatures to match {accept_algorithm}")
        filter_signatures(a, accept_algorithm)

    logger.info(f"Forwarding answer {q.id} for {host}:{port} ...")
    logger.info(indent(a.to_text()))
    return a.to_wire()


class ReusePortServer:

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()


class ReusingUDPServer(ReusePortServer, socketserver.UDPServer):
    pass


class ReusingTCPServer(ReusePortServer, socketserver.TCPServer):
    pass


class Handler(socketserver.BaseRequestHandler):
    SERVER = None

    @classmethod
    def serve(cls):
        logger.info(f"starting {cls.SERVER} in pid {os.getpid()}...")
        with cls.SERVER((HOST, PORT), cls) as server:
            server.serve_forever()

    def digest(self, data):
        try:
            return digest(data, self.client_address[0], self.client_address[1])
        except dns.exception.Timeout:
            logger.error(traceback.format_exc())


class UDPHandler(Handler):
    SERVER = ReusingUDPServer

    def handle(self):
        data = self.request[0]
        response = self.digest(data)
        if response is not None:
            self.request[1].sendto(response, self.client_address)


class TCPHandler(Handler):
    SERVER = ReusingTCPServer

    def handle(self):
        # self.request is the TCP socket connected to the client
        length = struct.unpack('!h', self.request.recv(2))[0]
        data = self.request.recv(length)
        response = self.digest(data)
        if response is not None:
            length = struct.pack('!h', len(response))
            self.request.sendall(length + response)


HOST, PORT = "0.0.0.0", 53
BE_EVIL = bool(os.environ.get("BE_EVIL", False))

if __name__ == "__main__":
    num_processes = int(os.environ.get("ADNSSEC_NUM_PROCESSES", 10))
    processes = [
        multiprocessing.Process(target=handler)
        for handler in [TCPHandler.serve, UDPHandler.serve]
        for _ in range(num_processes)
    ]
    for p in processes:
        logger.info(f"Starting {p} from pid {os.getpid()}")
        p.start()
    for p in processes:
        p.join()
