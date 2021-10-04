import logging
import multiprocessing
import os
import socket
import socketserver
import struct
import traceback
from typing import Optional, List

import dns.dnssec
import dns.message
import dns.query
import dns.rdtypes.ANY
import dns.rrset

IN = dns.rdataclass.from_text("IN")
TXT = dns.rdatatype.from_text("TXT")
A = dns.rdatatype.from_text("A")
RRSIG = dns.rdatatype.from_text("RRSIG")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_ns_addr = socket.gethostbyname(os.environ.get('AUTH_NS_HOST', 'ns'))
auth_ns_port = int(os.environ.get('AUTH_NS_PORT', 53))
IP_A_EVIL = os.environ.get('IP_A_EVIL', '127.6.6.6')


def indent(s, l=4):
    return " " * l + s.replace("\n", "\n" + " " * l)


def filter_response(a: dns.message.QueryMessage):
    qname = a.question[0].name
    if not qname[0].lower().startswith(b'mitm'):
        return

    def replace_rrsig_algo(section: List, replace_with):
        replace_with = int(replace_with)
        rrsigs = [rrset for rrset in section if rrset.rdtype == RRSIG]
        for rrsig in rrsigs:
            section.remove(rrsig)
            new_rrsig = dns.rrset.RRset(name=rrsig.name, rdclass=rrsig.rdclass, rdtype=rrsig.rdtype, covers=rrsig.covers)
            section.append(new_rrsig)
            for rr in rrsig:
                new_rrsig.add(dns.rdtypes.ANY.RRSIG.RRSIG(
                    rdclass=rr.rdclass,
                    rdtype=rr.rdtype,
                    type_covered=rr.type_covered,
                    algorithm=replace_with,
                    labels=rr.labels,
                    original_ttl=rr.original_ttl,
                    expiration=rr.expiration,
                    inception=rr.inception,
                    key_tag=rr.key_tag,
                    signer=rr.signer,
                    signature=rr.signature,
                ))

    def replace_a(section, *args):
        a_rrsets = [rrset for rrset in section if rrset.rdtype == A]
        for a in a_rrsets:
            section.remove(a)
            new_a = dns.rrset.RRset(name=a.name, rdclass=a.rdclass, rdtype=a.rdtype, covers=a.covers)
            section.append(new_a)
            new_a.add(dns.rdtypes.IN.A.A(
                rdclass=a[0].rdclass,
                rdtype=a[0].rdtype,
                address=IP_A_EVIL,
            ))

    def drop_rrsigs(section, algorithm):
        algorithm = dns.dnssec.Algorithm(int(algorithm))
        rrsigs = [rrset for rrset in section if rrset.rdtype == RRSIG]
        for rrsig in rrsigs:
            section.remove(rrsig)
            new_rrsig = dns.rrset.RRset(name=rrsig.name, rdclass=rrsig.rdclass, rdtype=rrsig.rdtype, covers=rrsig.covers)
            for rr in rrsig:
                if rr.algorithm != algorithm:
                    new_rrsig.add(dns.rdtypes.ANY.RRSIG.RRSIG(
                        rdclass=rr.rdclass,
                        rdtype=rr.rdtype,
                        type_covered=rr.type_covered,
                        algorithm=rr.algorithm,
                        labels=rr.labels,
                        original_ttl=rr.original_ttl,
                        expiration=rr.expiration,
                        inception=rr.inception,
                        key_tag=rr.key_tag,
                        signer=rr.signer,
                        signature=rr.signature,
                    ))
            if len(new_rrsig) > 0:
                section.append(new_rrsig)

    def add_bogus_rrsig(section, algorithm):
        algorithm = dns.dnssec.Algorithm(int(algorithm))
        rrsigs = [rrset for rrset in section if rrset.rdtype == RRSIG]
        for rrsig in rrsigs:
            section.remove(rrsig)
            new_rrsig = dns.rrset.RRset(name=rrsig.name, rdclass=rrsig.rdclass, rdtype=rrsig.rdtype, covers=rrsig.covers)
            section.append(new_rrsig)
            for rr in rrsig:
                new_rrsig.add(dns.rdtypes.ANY.RRSIG.RRSIG(
                    rdclass=rr.rdclass,
                    rdtype=rr.rdtype,
                    type_covered=rr.type_covered,
                    algorithm=rr.algorithm,
                    labels=rr.labels,
                    original_ttl=rr.original_ttl,
                    expiration=rr.expiration,
                    inception=rr.inception,
                    key_tag=rr.key_tag,
                    signer=rr.signer,
                    signature=rr.signature,
                ))
            new_rrsig.add(dns.rdtypes.ANY.RRSIG.RRSIG(
                rdclass=rr.rdclass,
                rdtype=rr.rdtype,
                type_covered=rr.type_covered,
                algorithm=algorithm,
                labels=rr.labels,
                original_ttl=rr.original_ttl,
                expiration=rr.expiration,
                inception=rr.inception,
                key_tag=rr.key_tag,
                signer=rr.signer,
                signature=b"\xff" * 24,
            ))

    def add_bogus_txt(section, *args):
        txts = [rrset for rrset in section if rrset.rdtype == TXT]
        for txt in txts:
            section.remove(txt)
            new_txt = dns.rrset.RRset(name=txt.name, rdclass=txt.rdclass, rdtype=txt.rdtype, covers=txt.covers)
            section.append(new_txt)
            for rr in txt:
                new_txt.add(dns.rdtypes.ANY.TXT.TXT(
                    rdclass=rr.rdclass,
                    rdtype=rr.rdtype,
                    strings=rr.strings,
                ))
            new_txt.add(dns.rdtypes.ANY.TXT.TXT(
                rdclass=rr.rdclass,
                rdtype=rr.rdtype,
                strings=(b"evil",),
            ))

    def modify_signatures(section, *args):
        rrsigs = [rrset for rrset in section if rrset.rdtype == RRSIG]
        for rrsig in rrsigs:
            section.remove(rrsig)
            new_rrsig = dns.rrset.RRset(name=rrsig.name, rdclass=rrsig.rdclass, rdtype=rrsig.rdtype, covers=rrsig.covers)
            section.append(new_rrsig)
            for rr in rrsig:
                s = rr.signature
                new_rrsig.add(dns.rdtypes.ANY.RRSIG.RRSIG(
                    rdclass=rr.rdclass,
                    rdtype=rr.rdtype,
                    type_covered=rr.type_covered,
                    algorithm=rr.algorithm,
                    labels=rr.labels,
                    original_ttl=rr.original_ttl,
                    expiration=rr.expiration,
                    inception=rr.inception,
                    key_tag=rr.key_tag,
                    signer=rr.signer,
                    signature=s[:-1] + bytes([s[-1] ^ 0x1]),  # flip last bit
                ))

    instruction_codes = {
        'rs': replace_rrsig_algo,
        'ra': replace_a,
        'ds': drop_rrsigs,
        'as': add_bogus_rrsig,
        'at': add_bogus_txt,
        'ms': modify_signatures,
        'mitm': lambda *args: None,  # no-op
    }

    actions = [
        (f, instruction[len(ic):])
        for instruction in qname[0].decode().lower().split('-')
        for ic, f in instruction_codes.items()
        if instruction.startswith(ic)
    ]

    def filter_section(section):
        for action, arg in actions:
            action(section, arg)
        return section

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

    if BE_EVIL:
        filter_response(a)

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
    num_processes = int(os.environ.get("ADNSSEC_NUM_PROCESSES", 100))
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
