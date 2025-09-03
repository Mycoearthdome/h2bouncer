#!/usr/bin/env python3
# Hardened HTTP/2 -> HTTP/1.1 streaming bouncer (single TLS port, force HTTP/2 via ALPN)

from __future__ import annotations
import sys, time, logging, signal, ipaddress, subprocess, urllib.parse
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Optional, Tuple, Set

from twisted.internet import reactor, task, defer, ssl as tssl
from twisted.internet.threads import deferToThread
from twisted.internet.protocol import Protocol, Factory, ClientFactory, ServerFactory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.internet.defer import Deferred
from twisted.protocols.policies import TimeoutMixin
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource
from twisted.web.client import FileBodyProducer
from twisted.internet.ssl import ContextFactory, optionsForClientTLS, CertificateOptions, PrivateCertificate, Certificate, KeyPair
from twisted.protocols.tls import TLSMemoryBIOProtocol, TLSMemoryBIOFactory
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol, SSL4ClientEndpoint
from twisted.internet.interfaces import ITransport
from zope.interface import implementer

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from collections import OrderedDict, namedtuple

# --- hyper-h2 imports ---
import h2.connection
import h2.events
import h2.config
import h2.settings
import h2.errors
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import (
    RequestReceived,
    ResponseReceived,
    DataReceived,
    StreamEnded,
    RemoteSettingsChanged,
    SettingsAcknowledged,
    WindowUpdated,
)
from h2.config import H2Configuration

from io import BytesIO
import urllib.request
from collections import deque
import socket
from urllib.parse import urlparse
import re
import zlib
import logging
import threading
import os



logging.basicConfig(level=logging.INFO)

# ---------- Configuration ----------
LISTEN_PORT = 6666
IP_REFRESH_INTERVAL = 3600

CACHE_TTL = 600  # seconds
_cert_cache: OrderedDict[str, Tuple[bytes, bytes, float]] = OrderedDict()

MAX_CONCURRENT_STREAMS_DEFAULT = 200
INITIAL_WINDOW_SIZE_DEFAULT = 256 * 1024
MAX_FRAME_SIZE_DEFAULT = 65536
MAX_BUFFER_PER_STREAM = 4 * 1024 * 1024
CONNECTION_IDLE_TIMEOUT = 300
STREAM_INACTIVITY_TIMEOUT = 120
STREAM_BODY_TIMEOUT = 60
METRICS_PORT = 9100
UPSTREAM_TIMEOUT = 30  # seconds

LOG_LEVEL = logging.INFO
logger = logging.getLogger("h2proxy")
logger.setLevel(LOG_LEVEL)
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(sh)

# ---------- SSRF & DNS helpers ----------
PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]
PRIVATE_V6_NETS = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("64:ff9b::/96"),        # NAT64 (not private, but often internal)
    ipaddress.ip_network("fc00::/7"),            # ULA
    ipaddress.ip_network("fe80::/10"),           # link-local
    ipaddress.ip_network("2001:db8::/32"),       # documentation
    ipaddress.ip_network("ff00::/8"),            # multicast
]

CERT_FILE = "root_ca.pem"
KEY_FILE = "root_ca.key"

from OpenSSL import crypto
import os, time

def load_or_create_root_ca(cert_file="root_ca.pem", key_file="root_ca.key"):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        with open(cert_file, "rb") as f:
            cert_data = f.read()
        with open(key_file, "rb") as f:
            key_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(int(time.time()))
        subj = cert.get_subject()
        subj.CN = "Bogus ROOT CA"
        subj.O = "Bogus Org"
        subj.C = "US"
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(subj)
        cert.set_pubkey(key)

        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])

        cert.sign(key, "sha256")

        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    return cert, key


def load_or_create_intermediate_ca(root_cert, root_key,
                                   cert_file="intermediate_ca.pem",
                                   key_file="intermediate_ca.key") -> tuple[bytes, bytes]:
    if os.path.exists(cert_file) and os.path.exists(key_file):
        with open(cert_file, "rb") as f:
            cert_pem = f.read()
        with open(key_file, "rb") as f:
            key_pem = f.read()
        return cert_pem, key_pem

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    cert = crypto.X509()
    subj = cert.get_subject()
    subj.C = "US"
    subj.O = "Bogus Intermediate"
    subj.CN = "Bogus Intermediate CA"

    cert.set_serial_number(int.from_bytes(os.urandom(16), "big"))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(root_cert.get_subject())
    cert.set_pubkey(key)

    exts = [
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=root_cert),
    ]
    cert.add_extensions(exts)

    cert.sign(root_key, "sha256")

    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    with open(cert_file, "wb") as f:
        f.write(cert_pem)
    with open(key_file, "wb") as f:
        f.write(key_pem)

    return cert_pem, key_pem


def generate_leaf_cert(hostname: str, ca_cert_pem: bytes, ca_key_pem: bytes):
    # Load CA from PEM
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_pem)

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(int.from_bytes(os.urandom(16), "big"))

    subj = cert.get_subject()
    subj.CN = hostname if len(hostname) <= 64 else "proxy-leaf"

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)

    san = f"DNS:{hostname}".encode("ascii")

    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature,keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
        crypto.X509Extension(b"subjectAltName", False, san),
    ])

    cert.sign(ca_key, "sha256")

    return (
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key),
    )


def load_cert_and_key(cert_pem: bytes, key_pem: bytes) -> tuple[crypto.X509, crypto.PKey]:
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
    return cert, key

def create_dynamic_tls_context(hostname: str) -> SSL.Context:
    leaf_pem, leaf_key = generate_cached_cert(hostname)
    leaf_cert, leaf_key_obj = load_cert_and_key(leaf_pem, leaf_key)

    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.use_certificate(leaf_cert)
    ctx.use_privatekey(leaf_key_obj)

    # Add intermediate
    interm_cert = crypto.load_certificate(crypto.FILETYPE_PEM, INTERM_CA_PEM)
    ctx.add_extra_chain_cert(interm_cert)

    # ALPN
    ctx.set_alpn_select_callback(lambda conn, protos: b"h2" if b"h2" in protos else b"http/1.1")
    ctx.set_cipher_list(b"ECDHE+AESGCM")
    return ctx

def make_dynamic_server_context(hostname: str):
    leaf_pem, leaf_key = generate_cached_cert(hostname)
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.set_options(SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    ctx.set_alpn_select_callback(lambda conn, protos: b"h2" if b"h2" in protos else b"http/1.1")
    ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, leaf_pem))
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, leaf_key))
    return ctx

def _is_ip_blocked(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        nets = PRIVATE_NETS if ip_obj.version == 4 else PRIVATE_V6_NETS
        return any(ip_obj in n for n in nets) or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local
    except Exception:
        return True  # be conservative

def enforce_ssrf_guard(hostname: str) -> None:
    """
    Enforce SSRF guard on a given hostname:
    - If it's an IP literal, check directly.
    - If it's a hostname, resolve it and check all returned IPs.
    """
    try:
        # Case 1: hostname is an IP literal
        ip_obj = ipaddress.ip_address(hostname)
        if _is_ip_blocked(str(ip_obj)):
            raise ValueError(f"Blocked IP address: {hostname}")
        return
    except ValueError:
        # Not an IP literal → must be hostname
        pass

    # Case 2: resolve domain to IPs
    try:
        infos = socket.getaddrinfo(hostname, None)
        resolved_ips = {info[4][0] for info in infos}
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {hostname}: {e}")

    for ip in resolved_ips:
        if _is_ip_blocked(ip):
            raise ValueError(f"Blocked IP resolution: {hostname} -> {ip}")

# ---------- Metrics ----------
USE_PROMETHEUS_CLIENT = False
metrics = {
    "requests_total": 0,
    "active_streams": 0,
    "bytes_in_total": 0,
    "bytes_out_total": 0,
    "streams_reset_total": 0,
    "ipset_refresh_count": 0
}
try:
    from prometheus_client import Counter, Gauge, Histogram, make_wsgi_app
    USE_PROMETHEUS_CLIENT = True
    PROM_REQUESTS = Counter("h2proxy_requests_total", "Total requests proxied")
    PROM_ACTIVE = Gauge("h2proxy_active_streams", "Active streams")
    PROM_BYTES_IN = Counter("h2proxy_bytes_in_total", "Bytes received")
    PROM_BYTES_OUT = Counter("h2proxy_bytes_out_total", "Bytes sent")
    PROM_RST = Counter("h2proxy_streams_reset", "Streams reset")
    PROM_STREAM_LATENCY = Histogram("h2proxy_stream_latency_seconds", "Stream duration")
except Exception:
    USE_PROMETHEUS_CLIENT = False

def safe_increment(metric_name, n=1):
    def _inc():
        old = metrics.get(metric_name, 0)
        new = old + n

        if metric_name == "active_streams":
            if new < 0:
                new = 0
            metrics[metric_name] = new
            if USE_PROMETHEUS_CLIENT:
                try:
                    PROM_ACTIVE.set(new)
                except Exception:
                    pass
            return

        if metric_name in ("requests_total", "bytes_in_total", "bytes_out_total", "streams_reset_total", "ipset_refresh_count"):
            if n > 0:
                metrics[metric_name] = new
                if USE_PROMETHEUS_CLIENT:
                    try:
                        if metric_name == "requests_total": PROM_REQUESTS.inc(n)
                        elif metric_name == "bytes_in_total": PROM_BYTES_IN.inc(n)
                        elif metric_name == "bytes_out_total": PROM_BYTES_OUT.inc(n)
                        elif metric_name == "streams_reset_total": PROM_RST.inc(n)
                    except Exception:
                        pass
            else:
                metrics[metric_name] = max(0, old + n)
        else:
            metrics[metric_name] = max(0, new)

    try:
        reactor.callFromThread(_inc)
    except Exception:
        _inc()

def incr_bytes_out(n: int): safe_increment("bytes_out_total", n)
def incr_bytes_in(n: int): safe_increment("bytes_in_total", n)
def incr_streams_reset(): safe_increment("streams_reset_total", 1)

ROOT_CA_PEM, ROOT_KEY_PEM = load_or_create_root_ca()

INTERM_CA_PEM, INTERM_KEY_PEM = load_or_create_intermediate_ca(ROOT_CA_PEM, ROOT_KEY_PEM)

def load_chain_from_files(cert_file, intermediates_files):
    # Load server cert
    with open(cert_file, "rb") as f:
        server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    # Load intermediates
    intermediates = []
    for path in intermediates_files:
        with open(path, "rb") as f:
            intermediates.append(crypto.load_certificate(crypto.FILETYPE_PEM, f.read()))

    return server_cert, intermediates

def create_ssl_context(cert_file, key_file, intermediates_files):
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)

    server_cert, intermediates = load_chain_from_files(cert_file, intermediates_files)
    
    # Set server cert
    ctx.use_certificate(server_cert)
    ctx.use_privatekey_file(key_file)

    # Add intermediates to the context
    for cert in intermediates:
        ctx.add_extra_chain_cert(cert)  # This works on Context, not Connection

    return ctx

def generate_cached_cert(hostname="localhost"):
    now = time.time()
    expired = [k for k,v in _cert_cache.items() if v[2] < now]
    for k in expired:
        del _cert_cache[k]

    MAX_CACHE_SIZE = 1000
    if len(_cert_cache) > MAX_CACHE_SIZE:
        for _ in range(len(_cert_cache) - MAX_CACHE_SIZE):
            _cert_cache.popitem(last=False)

    if hostname in _cert_cache:
        return _cert_cache[hostname][0], _cert_cache[hostname][1]

    # issue leaf signed by intermediate
    leaf_cert_pem, leaf_key_pem = generate_leaf_cert(hostname, INTERM_CA_PEM, INTERM_KEY_PEM)

    _cert_cache[hostname] = (leaf_cert_pem, leaf_key_pem, now + CACHE_TTL)
    return leaf_cert_pem, leaf_key_pem


# -----------------------------
# H2Bridge (hyper-h2) - maps client H2 <-> upstream H2
# -----------------------------
class H2Bridge:
    def __init__(self, proto, tls_upstream):
        """
        proto: ConnectProxyProtocol instance (reactor thread)
        tls_upstream: pyOpenSSL Connection (client-mode) over real socket (handshake done)
        """
        self.proto = proto
        self.tls_u = tls_upstream
        self.down_conn = H2Connection(config=H2Configuration(client_side=False))
        self.up_conn = H2Connection(config=H2Configuration(client_side=True))
        self.stream_map = {}     # client_stream_id -> upstream_stream_id
        self._running = True
        self._lock = threading.Lock()

        # init both sides; send connection preface/settings
        self.down_conn.initiate_connection()
        self.proto._downstream_send_plain(self.down_conn.data_to_send())

        self.up_conn.initiate_connection()
        self._send_to_upstream(self.up_conn.data_to_send())

        # thread to read plaintext from upstream TLS
        self.up_recv_thread = threading.Thread(target=self._upstream_recv_loop, daemon=True)
        self.up_recv_thread.start()

    def stop(self):
        self._running = False
        try:
            self.tls_u.close()
        except Exception:
            pass

    def _send_to_downstream(self, data):
        if data:
            self.proto._downstream_send_plain(data)

    def _send_to_upstream(self, data):
        if not data:
            return
        try:
            self.tls_u.send(data)
        except Exception as e:
            self.proto._log_err("send_to_upstream error: %s", e)

    # Call in reactor thread when plaintext from downstream arrives
    def receive_from_downstream_plaintext(self, data):
        events = self.down_conn.receive_data(data)
        for ev in events:
            if isinstance(ev, RequestReceived):
                headers = [(n, v) for n, v in ev.headers]
                u_stream = self.up_conn.get_next_available_stream_id()
                self.stream_map[ev.stream_id] = u_stream
                self.up_conn.send_headers(u_stream, headers, end_stream=False)
                self._send_to_upstream(self.up_conn.data_to_send())

            elif isinstance(ev, DataReceived):
                u_stream = self.stream_map.get(ev.stream_id)
                if u_stream is None:
                    continue
                self.up_conn.send_data(u_stream, ev.data, end_stream=False)
                self._send_to_upstream(self.up_conn.data_to_send())

                # acknowledge to client side
                self.down_conn.acknowledge_received_data(len(ev.data), ev.stream_id)
                self._send_to_downstream(self.down_conn.data_to_send())

            elif isinstance(ev, StreamEnded):
                u_stream = self.stream_map.get(ev.stream_id)
                if u_stream:
                    self.up_conn.end_stream(u_stream)
                    self._send_to_upstream(self.up_conn.data_to_send())

            # ignore other events for brevity

        pending = self.down_conn.data_to_send()
        if pending:
            self._send_to_downstream(pending)

    # thread: read plaintext HTTP/2 frames from upstream TLS, dispatch to reactor
    def _upstream_recv_loop(self):
        import time
        while self._running:
            try:
                data = self.tls_u.recv(65536)
            except SSL.WantReadError:
                time.sleep(0.01)
                continue
            except Exception:
                break
            if not data:
                break
            reactor.callFromThread(self._handle_upstream_data, data)

    def _handle_upstream_data(self, data):
        events = self.up_conn.receive_data(data)
        for ev in events:
            # map upstream -> client stream ids
            if isinstance(ev, ResponseReceived):
                client_stream = None
                for c, u in self.stream_map.items():
                    if u == ev.stream_id:
                        client_stream = c
                        break
                if client_stream is None:
                    continue
                headers = [(n, v) for n, v in ev.headers]
                self.down_conn.send_headers(client_stream, headers, end_stream=False)
                self._send_to_downstream(self.down_conn.data_to_send())

            elif isinstance(ev, DataReceived):
                client_stream = None
                for c, u in self.stream_map.items():
                    if u == ev.stream_id:
                        client_stream = c
                        break
                if client_stream is None:
                    continue
                self.down_conn.send_data(client_stream, ev.data, end_stream=False)
                self._send_to_downstream(self.down_conn.data_to_send())

                # ack upstream
                self.up_conn.acknowledge_received_data(len(ev.data), ev.stream_id)
                if self.up_conn.data_to_send():
                    self._send_to_upstream(self.up_conn.data_to_send())

            elif isinstance(ev, StreamEnded):
                client_stream = None
                for c, u in self.stream_map.items():
                    if u == ev.stream_id:
                        client_stream = c
                        break
                if client_stream:
                    self.down_conn.end_stream(client_stream)
                    self._send_to_downstream(self.down_conn.data_to_send())

        # send any pending frames upstream (e.g., SETTINGS ACK)
        to_up = self.up_conn.data_to_send()
        if to_up:
            self._send_to_upstream(to_up)


# --- memory-BIO helpers for downstream (client-facing) TLS ---
def tls_mem_flush_out(tls_conn, transport):
    """Drain TLS record bytes from the memory BIO to the network transport."""
    while True:
        try:
            out = tls_conn.bio_read(16384)
            if not out:
                break
            transport.write(out)
        except SSL.WantReadError:
            break


def tls_mem_feed_in(tls_conn, data):
    """Feed network bytes into the TLS memory BIO."""
    tls_conn.bio_write(data)


def make_downstream_server_tls_ctx(cert_pem_bytes, key_pem_bytes):
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem_bytes)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem_bytes)
    ctx.use_certificate(cert)
    ctx.use_privatekey(key)
    # prefer h2 to http/1.1 when client offers
    def alpn_cb(conn, protos):
        return b"h2" if b"h2" in protos else b"http/1.1"
    ctx.set_alpn_select_callback(alpn_cb)
    ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
    return ctx


# --- upstream TLS worker (threaded) ---
def start_upstream_tls_and_pump(client_proto, host, port):
    """
    Thread: connect to upstream host:port, do TLS handshake with SNI+ALPN,
    attach upstream TLS Connection to client_proto via reactor.callFromThread,
    then pump upstream->client plaintext by calling client_proto._downstream_send_plain
    """
    def run():
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        ctx.set_alpn_protos([b"h2", b"http/1.1"])

        try:
            sock = socket.create_connection((host, port))
        except Exception as e:
            logger.error("[Upstream] connect fail %s:%s %s", host, port, e)
            reactor.callFromThread(lambda: client_proto.transport.loseConnection())
            return

        tls_u = SSL.Connection(ctx, sock)
        try:
            tls_u.set_tlsext_host_name(host.encode("idna"))
        except Exception:
            pass
        tls_u.set_connect_state()

        try:
            tls_u.do_handshake()
            try:
                up_alpn = tls_u.get_alpn_proto_negotiated()
            except Exception:
                up_alpn = None
            logger.info("[Upstream] handshake OK %s:%s ALPN=%s", host, port, up_alpn)
        except Exception as exc:
            emsg = str(exc)
            logger.error("[Upstream] handshake fail %s", emsg)
            try:
                tls_u.close()
            except Exception:
                pass
            reactor.callFromThread(lambda: client_proto.transport.loseConnection())
            return

        # attach upstream to protocol (reactor thread)
        reactor.callFromThread(lambda: client_proto._attach_upstream(tls_u))

        # pump upstream -> client plaintext
        try:
            while True:
                try:
                    data = tls_u.recv(16384)
                except SSL.WantReadError:
                    # avoid busy loop
                    time.sleep(0.01)
                    continue
                except Exception:
                    break
                if not data:
                    break
                # schedule writing plaintext into downstream TLS in reactor
                reactor.callFromThread(lambda d=data: client_proto._downstream_send_plain(d))
        finally:
            try:
                tls_u.close()
            except Exception:
                pass
            reactor.callFromThread(lambda: client_proto.transport.loseConnection())

    t = threading.Thread(target=run, daemon=True)
    t.start()


# --- main protocol ---
class ConnectProxyProtocol(Protocol):
    def __init__(self):
        self._buf = b""
        self._tunneled = False
        self._host = None
        self._port = None

        # inner TLS (server-mode via memory BIO)
        self._tls_d = None
        self._downstream_hs_done = False

        # upstream TLS connection (pyOpenSSL.Connection)
        self._upstream = None

    # convenience logs
    def _log_info(self, *a): logger.info(*a)
    def _log_err(self, *a): logger.error(*a)

    def _attach_upstream(self, tls_conn):
        """Called in reactor thread when upstream TLS is ready"""
        self._upstream = tls_conn
        # If downstream handshake already done, we can proceed to exchange plaintext
        try:
            down_alpn = None
            up_alpn = None
            try:
                down_alpn = self._tls_d.get_alpn_proto_negotiated()
            except Exception:
                pass
            try:
                up_alpn = tls_conn.get_alpn_proto_negotiated()
            except Exception:
                pass
            self._log_info("attach_upstream: down_alpn=%s up_alpn=%s", down_alpn, up_alpn)
        except Exception as e:
            self._log_err("attach_upstream error: %s", e)

    def _downstream_send_plain(self, data):
        """
        Called in reactor thread with plaintext that must be encrypted to the client.
        Writes plaintext into server-mode memory BIO and flushes TLS records to transport.
        """
        if not self._tls_d:
            return
        try:
            self._tls_d.send(data)
        except SSL.WantWriteError:
            pass
        tls_mem_flush_out(self._tls_d, self.transport)

    # Twisted: plaintext data from outer TLS -> go into parsing CONNECT or into inner TLS bytes
    def dataReceived(self, data):
        # If CONNECT not processed yet, parse it
        if not self._tunneled:
            self._buf += data
            if b"\r\n\r\n" not in self._buf:
                return
            if not self._parse_and_ack_connect():
                return

            # Create per-host leaf cert for inner TLS and accept inner TLS via memory BIO
            try:
                cert_pem, key_pem = generate_cached_cert(self._host)
            except Exception as e:
                self._log_err("cert generation failed: %s", e)
                self.transport.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                self.transport.loseConnection()
                return

            ctx = make_downstream_server_tls_ctx(cert_pem, key_pem)
            self._tls_d = SSL.Connection(ctx, None)
            self._tls_d.set_accept_state()

            # flush any initial ServerHello etc
            tls_mem_flush_out(self._tls_d, self.transport)

            # Kick off upstream TLS thread (will attach upstream via callFromThread)
            start_upstream_tls_and_pump(self, self._host, self._port)
            return

        # After CONNECT ack: bytes belong to the inner TLS handshake/application
        if not self._tls_d:
            self.transport.loseConnection()
            return

        # Feed the bytes into the memory-BIO
        tls_mem_feed_in(self._tls_d, data)

        # Progress downstream handshake if needed
        if not self._downstream_hs_done:
            try:
                self._tls_d.do_handshake()
                self._downstream_hs_done = True
                try:
                    alpn = self._tls_d.get_alpn_proto_negotiated()
                except Exception:
                    alpn = None
                self._log_info("[Downstream] client handshake OK, ALPN=%s", alpn)
            except SSL.WantReadError:
                # need more bytes from client
                pass
            except SSL.WantWriteError:
                # OpenSSL wants to write records (flush below)
                pass
            except Exception as e:
                self._log_err("[Downstream] handshake fail: %s", e)
                self.transport.loseConnection()
                return

        # Flush any produced TLS records to client
        tls_mem_flush_out(self._tls_d, self.transport)

        # If handshake complete and upstream ready, move plaintext client->upstream
        if self._downstream_hs_done and self._upstream:
            while True:
                try:
                    plaintext = self._tls_d.recv(16384)
                except SSL.WantReadError:
                    break
                except Exception:
                    self.transport.loseConnection()
                    return
                if not plaintext:
                    self.transport.loseConnection()
                    return
                # send plaintext to upstream TLS
                try:
                    self._upstream.send(plaintext)
                except SSL.WantWriteError:
                    # upstream busy; minimal drop or you may buffer here
                    pass
                except Exception:
                    self.transport.loseConnection()
                    return

    def connectionLost(self, reason):
        try:
            if self._upstream:
                self._upstream.close()
        except Exception:
            pass
        self._log_info("connectionLost: %s", reason)

    def _parse_and_ack_connect(self):
        try:
            head, _ = self._buf.split(b"\r\n", 1)
            method, hostport, _ = head.split()
            if method.upper() != b"CONNECT":
                self.transport.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                self.transport.loseConnection()
                return False
            host, port_s = hostport.split(b":")
            self._host = host.decode()
            self._port = int(port_s)
        except Exception:
            self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            self.transport.loseConnection()
            return False

        self.transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunneled = True
        self._buf = b""
        self._log_info("[Proxy] CONNECT %s:%s", self._host, self._port)
        return True

# -----------------------------
# Helpful hexdump (short)
# -----------------------------
#def short_hexdump_labelled(label: str, data: bytes, max_bytes: int = 512) -> str:
#    if not data:
#        return f"{label}: (0 bytes)"
#    shown = data[:max_bytes]
#    hexpart = binascii.hexlify(shown).decode('ascii')
#    # ascii-friendly view (non-printable => .)
#    ascii_part = ''.join(ch if ch in string.printable and ch not in '\r\n\t' else '.' for ch in shown.decode('latin1'))
#    more = "..." if len(data) > max_bytes else ""
#    return f"{label}: {len(data)} bytes {more}\n  HEX: {hexpart}{more}\n  ASCII: {ascii_part}{more}"

#def hexdump_short(data, max_bytes=256):
#    shown = data[:max_bytes]
#    hexpart = binascii.hexlify(shown).decode('ascii')
#    ascii_part = ''.join(ch if ch in string.printable and ch not in '\r\n\t' else '.' for ch in shown.decode('latin1'))
#    more = '...' if len(data) > max_bytes else ''
#    return f"{len(data)} bytes{more}\n  HEX: {hexpart}{more}\n  ASCII: {ascii_part}{more}"


# -----------------------------
# Upstream proxy protocol (for raw TCP tunnel) -- enhanced logging
# -----------------------------
#class UpstreamProxyProtocol(Protocol):
#    def __init__(self, client_proto):
#        self.client_proto = client_proto
#        self._bytes_from_upstream = 0
#        self._first_upstream_hexdumped = False

#    def connectionMade(self):
#        # pair with the client
#        self.client_proto.upstream_proto = self
#        logger.info("UpstreamProxyProtocol.connectionMade -> paired with client")
#        # if client had buffered bytes, flush them now (client may have buffered clientHello)
#        if getattr(self.client_proto, "_buffered_after_connect", b""):
#            try:
#                data = self.client_proto._buffered_after_connect
#                logger.info("Flushing %d buffered bytes from client to upstream on connect", len(data))
#                self.transport.write(data)
#                # log first bytes that we forwarded
#                logger.info(short_hexdump_labelled("Client->Upstream (flushed buffered)", data, max_bytes=512))
#            except Exception:
#                logger.exception("Error flushing buffered data to upstream")
#            self.client_proto._buffered_after_connect = b''

#    def dataReceived(self, data):
#        # upstream -> proxy -> client
#        self._bytes_from_upstream += len(data)
#        # log first upstream bytes we receive (only once, to avoid log spam)
#        if not self._first_upstream_hexdumped:
#            logger.info(short_hexdump_labelled("Upstream->Proxy (first)", data, max_bytes=512))
#            self._first_upstream_hexdumped = True
#        try:
#            if self.client_proto and self.client_proto.transport:
#                self.client_proto.transport.write(data)
#                logger.debug("Forwarded %d bytes upstream->client (total from upstream: %d)", len(data), self._bytes_from_upstream)
#        except Exception:
#            logger.exception("Failed writing to client; closing both sides")
#            try: self.client_proto.transport.loseConnection()
#            except Exception: pass
#            try: self.transport.loseConnection()
#            except Exception: pass

#    def connectionLost(self, reason):
#        logger.info("Upstream connectionLost: %r", reason)
#        try:
#            if self.client_proto and self.client_proto.transport:
#                self.client_proto.transport.loseConnection()
#        except Exception:
#            pass


# -----------------------------
# CONNECT Proxy (client-facing) -- enhanced logging
# -----------------------------
#class ConnectProxyProtocol(Protocol):
#    def __init__(self):
#        self._buffer = b""
#        self._tunneled = False
#        self._host = None
#        self._port = None
#        self.upstream_proto = None
#        # buffer for bytes from client that arrive after CONNECT but before upstream ready
#        self._buffered_after_connect = b""
#        self._bytes_from_client = 0
#        self._bytes_to_client = 0
#        self._first_client_hexdumped = False

#    def dataReceived(self, data):
#        logger.debug("Client->proxy: dataReceived %d bytes (tunneled=%s)", len(data), self._tunneled)
#        # If we are already tunneled, *always* log the first chunk(s) from client
#        if self._tunneled:
#            # log raw bytes from client after CONNECT (this should include ClientHello)
#            logger.info("Client->proxy (post-CONNECT) raw chunk:\n%s", hexdump_short(data, max_bytes=512))

#        # If tunnel is established and we have an upstream, pipe raw bytes client->upstream.
#        if self._tunneled and self.upstream_proto and getattr(self.upstream_proto, "transport", None):
#            try:
#                self._bytes_from_client += len(data)
#                # log once the first client->upstream bytes (likely ClientHello)
#                if not self._first_client_hexdumped:
#                    logger.info(short_hexdump_labelled("Client->Upstream (first forwarded)", data, max_bytes=512))
#                    self._first_client_hexdumped = True
#                self.upstream_proto.transport.write(data)
#                logger.debug("Forwarded %d bytes client->upstream (total forwarded: %d)", len(data), self._bytes_from_client)
#            except Exception:
#                logger.exception("Failed writing to upstream; closing both sides")
#                try: self.upstream_proto.transport.loseConnection()
#                except Exception: pass
#                try: self.transport.loseConnection()
#                except Exception: pass
#            return

#        # If not yet tunneled, parse the CONNECT request header
#        self._buffer += data
#        if b"\r\n\r\n" not in self._buffer:
#            return

#        # Parse first line
#        try:
#            head, rest = self._buffer.split(b"\r\n\r\n", 1)
#            first_line, _ = head.split(b"\r\n", 1)
#            parts = first_line.split()
#            if len(parts) < 3:
#                raise ValueError("Bad request line")
#            method, hostport = parts[0], parts[1]
#            if method != b"CONNECT":
#                self.transport.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
#                self.transport.loseConnection()
#                return
#            # hostport looks like b"api.ipify.org:443"
#            host, port_s = hostport.split(b":", 1)
#            self._host = host.decode()
#            self._port = int(port_s)
#        except Exception:
#            self.transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
#            self.transport.loseConnection()
#            return

#        logger.info("Proxy CONNECT to %s:%d", self._host, self._port)
#        # Reply success and switch to tunneling mode (client will begin TLS handshake)
#        self.transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
#        self._tunneled = True

#        # If there was extra data beyond CONNECT headers (rare), buffer it to send to upstream
#        if rest:
#            self._buffered_after_connect += rest
#            logger.debug("Buffered %d extra bytes after CONNECT headers to send to upstream", len(rest))

#        # Initiate raw TCP connection to the requested upstream host:port and wire it
#        self._start_upstream_tunnel()

#        # reset header buffer
#        self._buffer = b""

#    def _start_upstream_tunnel(self):
#        logger.debug("Starting upstream tunnel to %s:%d", self._host, self._port)
#        ep = TCP4ClientEndpoint(reactor, self._host, self._port)
#        upstream_proto = UpstreamProxyProtocol(self)
#        d = connectProtocol(ep, upstream_proto)

#        def _cb(proto):
#            logger.info("Connected to upstream %s:%d", self._host, self._port)
#            # flush any buffered bytes we captured after CONNECT
#            if self._buffered_after_connect:
#                try:
#                    # log the buffered first bytes (this is often the ClientHello)
#                    logger.info(short_hexdump_labelled("Client->Upstream (buffered sent on connect)", self._buffered_after_connect, max_bytes=512))
#                    proto.transport.write(self._buffered_after_connect)
#                    logger.debug("Flushed %d buffered bytes to upstream", len(self._buffered_after_connect))
#                except Exception:
#                    logger.exception("Error flushing buffered bytes to upstream")
#                self._buffered_after_connect = b''
#            return proto

#        def _eb(f):
#            logger.exception("Failed to connect to upstream %s:%d: %s", self._host, self._port, f)
#            try: self.transport.loseConnection()
#            except Exception: pass

#        d.addCallbacks(_cb, _eb)

#    def connectionLost(self, reason):
#        logger.debug("Client connectionLost: %r", reason)
#        try:
#            if self.upstream_proto and getattr(self.upstream_proto, "transport", None):
#                self.upstream_proto.transport.loseConnection()
#        except Exception:
#            pass

# -----------------------------
# Proxy Factory
# -----------------------------
class ProxyFactory(Factory):
    def buildProtocol(self, addr):
        return ConnectProxyProtocol()

# -----------------------------
# ALPN Selector
# -----------------------------
class ALPNSelector(Protocol):
    def __init__(self):
        self._active_proto = None

    def connectionMade(self):
        # Pick fallback first (HTTP/1.1 CONNECT handler)
        self._active_proto = ConnectProxyProtocol()
        self._active_proto.makeConnection(self.transport)

        # Schedule ALPN negotiation check
        reactor.callLater(0, self._choose_alpn)

    def _choose_alpn(self):
        negotiated = getattr(self.transport, "negotiatedProtocol", None)
        if callable(negotiated):
            negotiated = negotiated()
        if isinstance(negotiated, bytes):
            negotiated = negotiated.decode("utf-8")
        logger.info("ALPN negotiated: %s", negotiated)
        if negotiated and negotiated.startswith("h2"):
            new_proto = H2ProxyProtocol()
            new_proto.makeConnection(self.transport)
            self._active_proto = new_proto

    def dataReceived(self, data):
        if self._active_proto:
            self._active_proto.dataReceived(data)

    def connectionLost(self, reason):
        if self._active_proto:
            self._active_proto.connectionLost(reason)

    
class MyCertificateOptions(tssl.CertificateOptions):
    def __init__(self, cert_pem, key_pem, sni_callback=None):
        super().__init__(
            privateKey=crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem),
            certificate=crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem),
            verify=False,
            enableSingleUseKeys=True
        )
        self._sni_callback = sni_callback

    def getContext(self):
        ctx = super().getContext()
        if self._sni_callback:
            ctx.set_tlsext_servername_callback(self._sni_callback)
        # ALPN protocols: prefer h2 over http/1.1
        ctx.set_alpn_select_callback(lambda conn, protos: b"h2" if b"h2" in protos else b"http/1.1")
        return ctx

class ProxyMultiplexer(Factory):
    # The factory returns an ALPN selector protocol which will pick the real app protocol
    def buildProtocol(self, addr):
        return ALPNSelector()

class DynamicContextFactory(ContextFactory):
    """
    Wrap an OpenSSL SSL.Context so Twisted can use it.
    """
    def __init__(self, root_cert, root_key):
        self.root_cert = root_cert
        self.root_key = root_key
        self._ctx = self._make_context()

    def _make_context(self):
        ctx = SSL.Context(SSL.TLS_SERVER_METHOD)

        # Load root CA for signing
        ctx.use_certificate(self.root_cert)
        ctx.use_privatekey(self.root_key)

        # Disable legacy protocols
        ctx.set_options(
            SSL.OP_NO_SSLv2 |
            SSL.OP_NO_SSLv3 |
            SSL.OP_NO_TLSv1 |
            SSL.OP_NO_TLSv1_1
        )

        # Advertise ALPN protocols (HTTP/2 first, then HTTP/1.1)
        try:
            ctx.set_alpn_select_callback(
                lambda conn, protos: b"h2" if b"h2" in protos else b"http/1.1"
            )
        except Exception as e:
            logger.warning("ALPN not available: %s", e)

        # Hook SNI → your dynamic leaf cert generator
        def sni_cb(conn):
            hostname = conn.get_servername().decode() if conn.get_servername() else "localhost"
            dyn_ctx = create_dynamic_tls_context(hostname)
            conn.set_context(dyn_ctx)

        ctx.set_tlsext_servername_callback(sni_cb)
        return ctx

    def getContext(self):
        return self._ctx
    
# ---------- Active H2 protocols ----------
_active_h2_protocols: Set["H2ProxyProtocol"] = set()

# ---------- Stream metadata ----------
class StreamMeta:
    __slots__ = (
        'stream_id', 'protocol_ref', 'chunks', 'buffered_bytes',
        'last_activity', 'closed', 'inactivity_call', 'body_timeout_call',
        'start_time', 'weight', 'depends_on', 'exclusive', 'method'
    )

    CHUNK_SIZE = 16 * 1024  # 16 KB per chunk

    def __init__(self, stream_id: int, proto, method: Optional[str] = None):
        self.stream_id = stream_id
        self.protocol_ref = proto
        self.chunks = deque()
        self.buffered_bytes = 0
        self.last_activity = time.time()
        self.closed = False
        self.inactivity_call = None
        self.body_timeout_call = None
        self.start_time = time.time()
        self.weight = None
        self.depends_on = None
        self.exclusive = None
        self.method = method

    def enqueue(self, data: bytes):
        if self.buffered_bytes + len(data) > MAX_BUFFER_PER_STREAM:
            self.reset_stream(h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
            return
        for i in range(0, len(data), self.CHUNK_SIZE):
            self.chunks.append(memoryview(data[i:i+self.CHUNK_SIZE]))
            self.buffered_bytes += len(data[i:i+self.CHUNK_SIZE])
        self.reset_inactivity_timer()

    def pop_chunk(self, max_size: int) -> Optional[bytes]:
        if not self.chunks:
            return None
        chunk = self.chunks.popleft()
        if len(chunk) > max_size:
            # split chunk
            self.chunks.appendleft(chunk[max_size:])
            chunk = chunk[:max_size]
        self.buffered_bytes -= len(chunk)
        self.last_activity = time.time()
        self.reset_inactivity_timer()
        return chunk.tobytes()

    def reset_inactivity_timer(self):
        if self.inactivity_call:
            try: self.inactivity_call.cancel()
            except Exception: pass
        self.inactivity_call = reactor.callLater(STREAM_INACTIVITY_TIMEOUT, self.on_inactive)

    def set_body_timeout(self):
        if self.body_timeout_call:
            try: self.body_timeout_call.cancel()
            except Exception: pass
        self.body_timeout_call = reactor.callLater(STREAM_BODY_TIMEOUT, self.on_body_timeout)

    def cancel_timers(self):
        if self.inactivity_call:
            try: self.inactivity_call.cancel()
            except Exception: pass
        if self.body_timeout_call:
            try: self.body_timeout_call.cancel()
            except Exception: pass

    def on_inactive(self):
        self.reset_stream(h2.errors.ErrorCodes.CANCEL, STREAM_INACTIVITY_TIMEOUT)

    def on_body_timeout(self):
        self.reset_stream(h2.errors.ErrorCodes.CANCEL, STREAM_BODY_TIMEOUT)

    def reset_stream(self, code, duration=None):
        try:
            code_int = int(code)
        except Exception:
            code_int = int(h2.errors.ErrorCodes.INTERNAL_ERROR)
        logger.warning("Stream %d reset: %s after %s sec; buffered_bytes=%d",
                       self.stream_id, code_int, duration, self.buffered_bytes)
        incr_streams_reset()
        try:
            self.protocol_ref.h2_conn.reset_stream(self.stream_id, error_code=code_int)
            self.protocol_ref.transport.write(self.protocol_ref.h2_conn.data_to_send())
        except Exception:
            pass
        self.clear()

    def clear(self):
        safe_increment("active_streams", -1)
        self.cancel_timers()
        try: del self.protocol_ref.stream_meta[self.stream_id]
        except KeyError: pass
        if USE_PROMETHEUS_CLIENT:
            duration = time.time() - self.start_time
            try: PROM_STREAM_LATENCY.observe(duration)
            except Exception: pass

# -----------------------------
# Upstream receiver (handles streaming data)
# -----------------------------
class UpstreamStreamReceiver(Protocol, TimeoutMixin):
    """
    Receives data from upstream (HTTP/1.1) and immediately forwards it
    to the H2 client using StreamMeta. Handles gzip/deflate by streaming
    decompressed bytes when available and flushing on connectionLost.
    """
    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta, encoding: Optional[str] = None):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta
        self.setTimeout(UPSTREAM_TIMEOUT)
        self.encoding = encoding
        self.decompressor = None
        self._decompress_buf = b""

        if encoding == "gzip":
            # gzip with header detection (windowBits = 16 + MAX_WBITS)
            self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            self.decompressor = zlib.decompressobj()

    def _send_to_h2(self, data: bytes):
        if not data:
            return
        try:
            self.h2_protocol.h2_conn.send_data(self.meta.stream_id, data)
            self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            incr_bytes_out(len(data))
        except Exception:
            logger.exception("Failed sending data to H2 stream %d", self.meta.stream_id)
            # if sending fails, reset the stream
            try:
                self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
            except Exception:
                pass

    def dataReceived(self, data: bytes):
        if not data:
            return

        if self.decompressor:
            try:
                out = self.decompressor.decompress(data)
            except Exception:
                logger.exception("Decompression error for stream %d", self.meta.stream_id)
                # If decompression fails, reset stream
                self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
                return

            if out:
                self._send_to_h2(out)
            # there may be buffered decompressed data available only after flush;
            # do NOT emit end_stream here; wait for upstream close which will flush.
        else:
            # no decompression => send immediately
            self._send_to_h2(data)

    def connectionLost(self, reason):
        """
        Upstream closed: flush decompressor (if any), then flush any queued
        chunks from the stream meta and finally send END_STREAM once.
        """
        logger.debug("Upstream connectionLost for stream %d: %r", self.meta.stream_id, reason)
        self.meta.closed = True

        # Flush decompressor if present
        if self.decompressor:
            try:
                remaining = self.decompressor.flush()
                if remaining:
                    self._send_to_h2(remaining)
            except Exception:
                logger.exception("Error flushing decompressor for stream %d", self.meta.stream_id)
                # continue to try to close stream

        # Send any buffered chunks queued on StreamMeta (body we accepted from client)
        try:
            while True:
                chunk = self.meta.pop_chunk(self.h2_protocol.max_frame_size)
                if not chunk:
                    break
                self.h2_protocol.h2_conn.send_data(self.meta.stream_id, chunk)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
                incr_bytes_out(len(chunk))
        except Exception:
            logger.exception("Error flushing StreamMeta buffer for stream %d", self.meta.stream_id)
            try:
                self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
            except Exception:
                pass

        # Finally, ensure a single END_STREAM is sent for this H2 stream
        try:
            self.h2_protocol.h2_conn.send_data(self.meta.stream_id, b'', end_stream=True)
            self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
        except Exception:
            logger.exception("Failed to send END_STREAM for stream %d", self.meta.stream_id)
            try:
                self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
            except Exception:
                pass

    def timeoutConnection(self):
        # Upstream timeout: cancel the stream.
        if self.meta and not self.meta.closed:
            logger.warning("Upstream timeout for stream %d", self.meta.stream_id)
            self.meta.reset_stream(h2.errors.ErrorCodes.CANCEL)
        try:
            self.transport.loseConnection()
        except Exception:
            pass

# -----------------------------
# Upstream request (SSRF-safe + SNI)
# -----------------------------
class UpstreamAgentRequest:
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(self, h2_protocol: "H2ProxyProtocol", meta: StreamMeta,
                 method: str, absolute_url: str, headers: List[Tuple[str, str]]):
        self.h2_protocol = h2_protocol
        self.meta = meta
        self.method = method.encode() if isinstance(method, str) else method
        self.url = absolute_url
        self.headers = [
            (k.lower(), v) for k, v in headers
            if k.lower() not in ("connection","proxy-connection","keep-alive",
                                 "transfer-encoding","upgrade","te","alt-svc")
        ]
        self.agent_http = h2_protocol.agent_http
        self.agent_https = h2_protocol.agent_https

    def start(self, attempt=1):
        parsed = urlparse(self.url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme=="https" else 80)

        # SSRF check in thread
        d = deferToThread(self._resolve_safe_ip, host, port)
        d.addCallback(lambda _: self._issue_request(parsed, attempt))
        d.addErrback(lambda f: self._handle_dns_failure(f, attempt))
        return d

    def _resolve_safe_ip(self, host, port):
        enforce_ssrf_guard(host)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        safe_ips = [info[4][0] for info in infos if not _is_ip_blocked(info[4][0])]
        if not safe_ips:
            raise ValueError(f"No safe IPs for {host}")
        return safe_ips[0]

    def _issue_request(self, parsed, attempt):
        # Rebuild the upstream URL properly
        upstream_url = urlunparse((
            parsed.scheme,           # http or https
            parsed.netloc,           # host[:port]
            parsed.path or "/",      # path
            parsed.params,           # rarely used
            parsed.query,            # query string (kept as-is)
            parsed.fragment          # fragment (kept as-is)
        ))

        request_target = urlunparse((
            "",          # scheme
            "",          # netloc
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        # Use original hostname for HTTPS (SNI correct)
        agent = self.agent_https if parsed.scheme == "https" else self.agent_http
        hdrs = Headers()
        for k, v in self.headers:
            hdrs.addRawHeader(k.encode(), v.encode())

        # Ensure Host header
        if not any(k.lower() == "host" for k, _ in self.headers):
            hdrs.addRawHeader(b"host", parsed.netloc.encode())

        # === DEBUG: print upstream request ===
        print("=== Upstream HTTP/1.1 Request ===")
        print(f"{self.method.decode()} {request_target} HTTP/1.1")
        for k, v in self.headers:
            print(f"{k}: {v}")
        print("=================================")

        # Prepare body if present
        body_data = b''.join(self.meta.chunks) if self.meta.chunks else None
        body_producer = FileBodyProducer(BytesIO(body_data)) if body_data else None

        # Make the request
        d = agent.request(self.method, upstream_url.encode(), headers=hdrs, bodyProducer=body_producer)

        timeout_call = reactor.callLater(UPSTREAM_TIMEOUT, lambda: d.cancel())

        def on_response(resp):
            if timeout_call.active():
                timeout_call.cancel()

            status = resp.code
            h2_headers = [(":status", str(status))]
            encoding = None
            for name, vals in resp.headers.getAllRawHeaders():
                lname = name.decode().lower()
                val = b", ".join(vals).decode()
                if lname in ("connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "alt-svc"):
                    continue
                if lname == "content-encoding":
                    encoding = val.lower()
                    continue
                h2_headers.append((lname, val))

            # Hardened defaults
            if not any(k.lower() == "x-content-type-options" for k, _ in h2_headers):
                h2_headers.append(("x-content-type-options", "nosniff"))
            if not any(k.lower() == "referrer-policy" for k, _ in h2_headers):
                h2_headers.append(("referrer-policy", "no-referrer"))

            # Send headers immediately
            try:
                self.h2_protocol.h2_conn.send_headers(self.meta.stream_id, h2_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception:
                pass

            # Deliver body to receiver
            receiver = UpstreamStreamReceiver(self.h2_protocol, self.meta, encoding=encoding)
            resp.deliverBody(receiver)
            return resp

        def on_error(f):
            if timeout_call.active(): timeout_call.cancel()
            if self.meta.closed: return
            if f.check(defer.CancelledError):
                logger.warning("Upstream fetch cancelled for stream %d", self.meta.stream_id)
                self.meta.reset_stream(h2.errors.ErrorCodes.CANCEL)
                return
            if attempt < self.MAX_RETRIES:
                logger.warning("Upstream fetch failed, retry %d/%d: %s", attempt, self.MAX_RETRIES, f)
                reactor.callLater(self.RETRY_DELAY, lambda: self.start(attempt + 1))
            else:
                logger.error("Upstream fetch failed for stream %d: %s", self.meta.stream_id, f)
                self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)

        d.addCallbacks(on_response, on_error)
        return d

    def _handle_dns_failure(self, failure, attempt):
        logger.warning("DNS resolution failed for %s: %s", self.url, failure)
        if attempt < self.MAX_RETRIES:
            reactor.callLater(self.RETRY_DELAY, lambda: self.start(attempt+1))
        else:
            self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)

# ---------------------------------------------------------------------
# H2 protocol implementation (server-side) -- unchanged
# ---------------------------------------------------------------------
class H2ProxyProtocol:
    def __init__(self):
        self.transport = None
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        self.h2_conn = h2.connection.H2Connection(config=cfg)
        self.stream_meta: Dict[int, StreamMeta] = {}
        self.waiters: List[Deferred] = []
        self.sending = False
        self.max_concurrent_streams = MAX_CONCURRENT_STREAMS_DEFAULT
        self.max_frame_size = MAX_FRAME_SIZE_DEFAULT
        # idle timer will be set in connection wrapper
        self._idle_call = None
        # Separate Agents to make intent clear: both are HTTP/1.1 clients.
        self.agent_http = Agent(reactor)  # plain HTTP/1.1
        self.agent_https = Agent(reactor, BrowserLikePolicyForHTTPS())  # HTTPS over TLS (still H1)
        self._sending_loop_active = False

    def makeConnection(self, transport):
        self.transport = transport
        # Initiate HTTP/2 connection and send initial settings
        self.h2_conn.initiate_connection()
        settings = {
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 65535,
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: self.max_frame_size
        }
        self.h2_conn.update_settings(settings)
        self.transport.write(self.h2_conn.data_to_send())
        # Start idle timer
        self._idle_call = reactor.callLater(60, self.on_connection_idle)

    # Connection idle handler
    def on_connection_idle(self):
        # If there are active streams, extend idle timer; otherwise close
        if any(not s.closed for s in self.stream_meta.values()):
            self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
            return
        # Graceful close
        try:
            self.shutdown(error=h2.errors.ErrorCodes.NO_ERROR)
        except Exception:
            try:
                self.transport.loseConnection()
            except Exception:
                pass
            
    def handle_request(self, event: h2.events.RequestReceived):
        safe_increment("requests_total", 1)

        # Reset idle timer
        try:
            if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                self._idle_call.cancel()
        except Exception:
            pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # Decode and normalize headers
        headers: List[Tuple[str, str]] = [
            (k.decode() if isinstance(k, bytes) else k,
            v.decode() if isinstance(v, bytes) else v)
            for k, v in event.headers
        ]
        headers = [(k.lower(), v) for k, v in headers]

        def send_h2_response(status_code: int):
            try:
                hdrs = [(":status", str(status_code)), ("content-length", "0")]
                self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
            except Exception:
                pass

        # Extract pseudo-headers
        method = next((v for (k, v) in headers if k == ":method"), None)
        path = next((v for (k, v) in headers if k == ":path"), None)
        scheme = next((v for (k, v) in headers if k == ":scheme"), None)
        authority = next((v for (k, v) in headers if k == ":authority"), None)

        if not all([method, path, scheme, authority]):
            try:
                self.h2_conn.reset_stream(event.stream_id, error_code=int(h2.errors.ErrorCodes.PROTOCOL_ERROR))
                self.transport.write(self.h2_conn.data_to_send())
            except Exception:
                pass
            return

        # --- Firefox HTTPS proxy support ---
        if method == "CONNECT":
            host, port = authority.split(":")
            logger.info("CONNECT request for %s:%s", host, port)

            # Send 200 back so browser thinks tunnel is ready
            response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
            self.transport.write(response)

            # Now switch protocol: wrap self.transport with TLS using our dynamic cert
            ctx = create_dynamic_tls_context(host)
            self.transport.startTLS(ctx, serverSide=True)

            # From here on, ALPN negotiates h2 with Firefox
            self.h2_conn.initiate_connection()
            self.transport.write(self.h2_conn.data_to_send())
            return

        # Concurrency guard
        if len(self.stream_meta) >= self.max_concurrent_streams:
            send_h2_response(503)
            incr_streams_reset()
            return

        # Normalize absolute URL
        if path.startswith("/") and re.match(r"^https?://", path, re.IGNORECASE):
            absolute_url = path
        elif re.match(r"^https?://", path, re.IGNORECASE):
            absolute_url = path
        else:
            absolute_url = f"{scheme}://{authority}{path}"

        parsed = urlparse(absolute_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            send_h2_response(400)
            return

        # SSRF guard
        try:
            enforce_ssrf_guard(parsed.hostname or "")
        except Exception as e:
            logger.warning("SSRF guard blocked request to %s: %s", path, e)
            send_h2_response(403)
            return

        # Stream meta tracking
        meta = StreamMeta(event.stream_id, self, method=method)
        self.stream_meta[event.stream_id] = meta
        safe_increment("active_streams", 1)

        # Build upstream headers
        upstream_headers = [
            (k, v) for (k, v) in headers if not k.startswith(":") and k != "host"
        ]
        upstream_headers.append(("host", parsed.netloc))
        if not any(k == "accept-encoding" for (k, _v) in upstream_headers):
            upstream_headers.append(("accept-encoding", "gzip, deflate"))

        # Start upstream request
        UpstreamAgentRequest(self, meta, method, absolute_url, upstream_headers).start()

    def dataReceived(self, data: bytes):
        # reset idle timer
        try:
            if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                try:
                    self._idle_call.cancel()
                except Exception:
                    pass
        except Exception:
            pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # parse events from h2
        try:
            events = self.h2_conn.receive_data(data)
        except Exception:
            # protocol error: send GOAWAY and close
            self.shutdown(error=h2.errors.ErrorCodes.PROTOCOL_ERROR)
            return

        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.handle_request(event)

            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                incr_bytes_in(len(event.data))
                meta = self.stream_meta.get(sid)
                if meta:
                    meta.enqueue(event.data)  # queue body for upstream
                    meta.set_body_timeout()
                    try:
                        self.h2_conn.acknowledge_received_data(len(event.data), sid)
                    except Exception:
                        pass

            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if meta:
                    meta.closed = True
                try:
                    if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                        try:
                            self._idle_call.cancel()
                        except Exception:
                            pass
                except Exception:
                    pass
                self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

            elif isinstance(event, h2.events.WindowUpdated):
                # remote increased our outbound window: wake send loop
                self._wake_waiters()
                self.maybe_send_queued_data()

            elif isinstance(event, h2.events.RemoteSettingsChanged):
                changed = event.changed_settings
                if h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS in changed:
                    try:
                        self.max_concurrent_streams = int(changed[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS].new_value)
                    except Exception:
                        pass
                if h2.settings.SettingCodes.MAX_FRAME_SIZE in changed:
                    try:
                        self.max_frame_size = int(changed[h2.settings.SettingCodes.MAX_FRAME_SIZE].new_value)
                    except Exception:
                        pass

            elif isinstance(event, h2.events.SettingsAcknowledged):
                logger.debug("Client acknowledged our SETTINGS")

            elif isinstance(event, h2.events.PingReceived):
                # reply with PING ACK (RFC 7540 §6.7)
                try:
                    # h2 provides ping_acknowledge or ping_reply depending on version
                    try:
                        self.h2_conn.ping_acknowledge(event.ping_data)
                    except AttributeError:
                        # fallback
                        self.h2_conn.ping(event.ping_data, ack=True)
                    self.transport.write(self.h2_conn.data_to_send())
                except Exception:
                    pass

            elif isinstance(event, h2.events.PriorityUpdated):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if meta is None:
                    meta = StreamMeta(sid, self)
                    self.stream_meta[sid] = meta
                meta.weight = event.weight
                meta.depends_on = event.depends_on
                meta.exclusive = event.exclusive

            elif isinstance(event, h2.events.StreamReset):
                sid = event.stream_id
                if sid in self.stream_meta:
                    try:
                        self.stream_meta[sid].clear()
                    except Exception:
                        pass
                try:
                    if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                        try:
                            self._idle_call.cancel()
                        except Exception:
                            pass
                except Exception:
                    pass
                self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # After processing events, try to send any queued frames
        self.maybe_send_queued_data()
        try:
            self.transport.write(self.h2_conn.data_to_send())
        except Exception:
            pass

    def _wake_waiters(self):
        waiters = list(self.waiters)
        self.waiters.clear()
        for d in waiters:
            try:
                d.callback(None)
            except Exception:
                pass

    def wait_for_window(self) -> Deferred:
        d = Deferred()
        self.waiters.append(d)
        return d

    def maybe_send_queued_data(self):
        # always schedule _send_loop on next reactor tick
        reactor.callLater(0, self._send_loop)

    def _send_loop(self):
        self._sending_loop_active = True
        try:
            for stream_id, meta in list(self.stream_meta.items()):
                if meta.closed and meta.buffered_bytes == 0:
                    continue
                while self.h2_conn.remote_flow_control_window(stream_id) > 0:
                    chunk = meta.pop_chunk(self.max_frame_size)
                    if not chunk:
                        break
                    try:
                        self.h2_conn.send_data(stream_id, chunk)
                        self.transport.write(self.h2_conn.data_to_send())
                        incr_bytes_out(len(chunk))
                    except Exception:
                        meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
        finally:
            self._sending_loop_active = False

    def initiate_push(self, parent_stream_id: int, link_path: str):
        return 

    def shutdown(self, error=h2.errors.ErrorCodes.NO_ERROR):
        """Send GOAWAY and close connection gracefully (RFC 7540 §6.8)."""
        try:
            last_sid = max(self.stream_meta.keys()) if self.stream_meta else 0
            # Some h2 versions accept 'last_stream_id' arg name
            try:
                self.h2_conn.close_connection(error_code=int(error), last_stream_id=last_sid)
            except TypeError:
                # fallback if different signature
                self.h2_conn.close_connection(error_code=int(error))
            self.transport.write(self.h2_conn.data_to_send())
        except Exception:
            pass
        try:
            self.transport.loseConnection()
        except Exception:
            pass

# ---------- TLS Listener (wrapper) ----------
class H2ProtocolWrapper(Protocol):
    def connectionMade(self):
        # instantiate the core protocol implementation and register
        self.h2 = H2ProxyProtocol()
        # set idle timer for the created H2ProxyProtocol
        try:
            self.h2._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.h2.on_connection_idle)
        except Exception:
            pass
        # add to global active set for graceful shutdown
        _active_h2_protocols.add(self.h2)
        try:
            # write initial frames (H2Connection.initiate_connection called in H2ProxyProtocol.__init__)
            self.transport.write(self.h2.h2_conn.data_to_send())
        except Exception:
            pass

    def connectionLost(self, reason=None):
        try:
            _active_h2_protocols.discard(self.h2)
            if self.h2_proto:
                try:
                    self.h2_proto.shutdown()
                except Exception:
                    pass
        except Exception:
            pass

    def dataReceived(self, data):
        self.h2.dataReceived(data)
        if not self.h2_proto:
            # decide protocol (H2 vs fallback)
            negotiated = getattr(self.transport, "negotiatedProtocol", lambda: None)()
            if negotiated == b"h2":
                self.h2_proto = H2ProxyProtocol()
            else:
                # fallback for plain HTTP/1.1 CONNECT
                self.h2_proto = ConnectProxyProtocol()
                self.h2_proto.factory = self.factory
            self.h2_proto.connectionMade()
        self.h2_proto.dataReceived(data)


def start_tls_listener():
    cert, key = load_or_create_root_ca()
    ctx_factory = DynamicContextFactory(cert, key)
    factory = ProxyMultiplexer()

    # This is the simple, correct path: let Twisted drive the TLS layer.
    reactor.listenSSL(LISTEN_PORT, factory, ctx_factory)
    logger.info("TLS listener started on port %d (HTTP/2 via ALPN)", LISTEN_PORT)
    reactor.run()
    
# ---------- Metrics server ----------
def start_metrics_server():
    if USE_PROMETHEUS_CLIENT:
        app = make_wsgi_app()
        root = WSGIResource(reactor, reactor.getThreadPool(), app)
        reactor.listenTCP(METRICS_PORT, Site(root))

# ---------- Signal Handling ----------
def shutdown_all(*args):
    logger.info("Shutdown requested - sending GOAWAY to all active connections")
    # iterate snapshot
    for proto in list(_active_h2_protocols):
        try:
            proto.shutdown(error=h2.errors.ErrorCodes.NO_ERROR)
        except Exception:
            pass
    # stop reactor after a short grace to allow frames to flush
    reactor.callLater(0.5, reactor.stop)

signal.signal(signal.SIGINT, shutdown_all)
signal.signal(signal.SIGTERM, shutdown_all)

if __name__ == "__main__":
    start_tls_listener()
    start_metrics_server()
