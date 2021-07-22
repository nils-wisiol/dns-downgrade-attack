import logging
import os
import socket
import socketserver
import struct
import threading
import traceback
from typing import List, Set, Optional, Dict

import dns.message
import dns.query
import pandas as pd
import sklearn as sk
import sklearn.tree

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

upstream_ns = socket.gethostbyname(os.environ.get('ADNSSEC_UPSTREAM_HOST', 'ns'))
upstream_port = int(os.environ.get('ADNSSEC_UPSTREAM_PORT', 53))

AC = 14  # our made-up edns flag for "agile cryptography"
ML_SELECTION = bool(os.environ.get('ADNSSEC_ML', False))

tree = {}
ALGO_NAME = {
    5: 'rsasha1',
    7: 'rsasha1nsec3sha1',
    8: 'rsasha256',
    10: 'rsasha512',
    13: 'ecdsap256sha256',
    14: 'ecdsap384sha384',
    15: 'ed25519',
    16: 'ed448',
}
ALGO_NUM = {name: num for num, name in ALGO_NAME.items()}
priority = [ALGO_NAME[key] for key in sorted(ALGO_NAME.keys())]
features = []


def train_classifiers() -> Dict[int, sk.tree.DecisionTreeClassifier]:
    data = {
        name: pd.read_pickle(f'/data/ml_data_{name}.pickle')
        for name in ALGO_NAME.values()
    }
    features.extend(list(filter(lambda c: c.startswith('feature_dns'), next(iter(data.values())).keys())))
    label = 'label_rcode0andad1'
    logger.info(f"Using features {features} to predict label {label}")

    for algo, d in data.items():
        X = d[features]
        Y = d[label]
        tree[algo] = sk.tree.DecisionTreeClassifier()
        tree[algo] = tree[algo].fit(X, Y)


def indent(s, l=4):
    return " " * l + s.replace("\n", "\n" + " " * l)


def filter_signatures(a: dns.message.QueryMessage, algs: Set[int] = None):
    algs = algs or {15}

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
                filtered_section.append(rrset)
        return filtered_section

    a.answer = filter_section(a.answer)
    a.authority = filter_section(a.authority)
    a.additional = filter_section(a.additional)


def predict_supported_algorithm(q: dns.message.QueryMessage, a: dns.message.QueryMessage) -> Set[int]:
    rrsig_algorithms = [
        {int(rr.algorithm) for rr in rrset.items}
        for rrset in a.answer if rrset.rdtype == dns.rdatatype.RdataType.RRSIG
    ]
    if not rrsig_algorithms:
        return set()
    available_algorithms = set.intersection(*rrsig_algorithms)
    if len(available_algorithms) == 1:
        return available_algorithms
    edns_options = set().union({int(o.otype) for i in q.opt.items for o in i.options}) if q.opt else set()
    feature_values = [
        q.flags & dns.flags.QR == 1,  # 'feature_dns_qr'
        q.opcode(),  # 'feature_dns_opcode'
        q.flags & dns.flags.AA == 1,  # 'feature_dns_aa'
        q.flags & dns.flags.TC == 1,  # 'feature_dns_tc'
        q.flags & dns.flags.RD == 1,  # 'feature_dns_rd'
        q.flags & dns.flags.RA == 1,  # 'feature_dns_ra'
        0,  # 'feature_dns_z'
        q.flags & dns.flags.CD == 1,  # 'feature_dns_cd'
        q.rcode(),  # 'feature_dns_rcode'
        len(q.question),  # 'feature_dns_qdcount'
        len(q.answer),  # 'feature_dns_ancount'
        len(q.authority),  # 'feature_dns_nscount',
        len(q.additional),  # 'feature_dns_arcount',
        q.opt.rdclass,  # 'feature_dns_edns_requestors_udp_payload_size',
        any(not (str(rr.name).islower() or str(rr.name).isupper()) for rr in q.question),
        # feature_dns_edns_requestors_udp_payload_size
        10 in edns_options,  # 'feature_dns_edns_cookie'
        8 in edns_options,  # 'feature_dns_edns_subnet'
    ]
    logger.info(dict(zip(features, feature_values)))
    supported_algorithms = {algo for algo in available_algorithms if tree[ALGO_NAME[algo]].predict([feature_values])[0]}
    logger.info(f"predicted support: {supported_algorithms}")
    selected_algorithms = {max(supported_algorithms)} if supported_algorithms else available_algorithms
    logger.info(f"Selected {selected_algorithms} out of available signature algorithms {available_algorithms}")
    return selected_algorithms


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
    a = dns.query.tcp(q, where=upstream_ns, port=upstream_port, timeout=1)
    logger.info(f"Received upstream answer for {q.id}, {host}:{port} ...")
    logger.info(indent(a.to_text()))

    accept_algorithm = {}  # all
    if ML_SELECTION:
        accept_algorithm = predict_supported_algorithm(m, a)
    if q.opt:
        for opt in next(iter(q.opt.items)).options:
            if opt.otype == AC:  # AC OPT option
                accept_algorithm = {b for b in opt.data}

    if accept_algorithm:
        logger.info(f"Filtering for signatures to match {accept_algorithm}")
        filter_signatures(a, accept_algorithm)

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

logger.info("Training classifiers ...")
train_classifiers()
logger.info("Training completed.")

if __name__ == "__main__":
    threading.Thread(target=UDPHandler.serve).start()
    threading.Thread(target=TCPHandler.serve).start()
