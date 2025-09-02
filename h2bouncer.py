#!/usr/bin/env python3
# Hardened HTTP/2 -> HTTP/1.1 streaming bouncer (single TLS port, force HTTP/2 via ALPN)

from __future__ import annotations
import sys, time, logging, signal, ipaddress, subprocess, urllib.parse
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Optional, Tuple, Set

from twisted.internet import reactor, task, defer, ssl as tssl
from twisted.internet.threads import deferToThread
from twisted.internet.protocol import Protocol, Factory, ClientFactory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.internet.defer import Deferred
from twisted.protocols.policies import TimeoutMixin
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource
from twisted.web.client import FileBodyProducer
from twisted.internet.ssl import ContextFactory
from twisted.protocols.tls import TLSMemoryBIOProtocol, TLSMemoryBIOFactory
from twisted.internet.endpoints import TCP4ServerEndpoint

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from collections import OrderedDict

import h2.connection
import h2.events
import h2.config
import h2.settings
import h2.errors
import os

from io import BytesIO
import urllib.request
from collections import deque
import socket
from urllib.parse import urlparse
import re
import zlib
import logging
import secrets

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


# --- CONNECT tunnel implementation (Twisted-friendly, bidirectional) ---
class UpstreamProtocol(Protocol):
    def __init__(self, client_proto, buffer=None):
        self.client_proto = client_proto
        self.buffer = buffer

    def connectionMade(self):
        # link upstream to client
        self.client_proto.upstream_proto = self

        # flush any buffered client bytes
        if self.buffer:
            data = self.buffer.getvalue()
            if data:
                self.transport.write(data)
            self.buffer = None

    def dataReceived(self, data):
        if self.client_proto and self.client_proto.transport:
            self.client_proto.transport.write(data)

    def connectionLost(self, reason):
        if self.client_proto and self.client_proto.transport:
            self.client_proto.transport.loseConnection()

class UpstreamFactory(ClientFactory):
    def __init__(self, client_proto, buffer):
        self.client_proto = client_proto
        self.buffer = buffer

    def buildProtocol(self, addr):
        # pass the protocol itself, not its transport
        return UpstreamProtocol(self.client_proto, buffer=self.buffer)

    def clientConnectionFailed(self, connector, reason):
        if self.client_proto and self.client_proto.transport:
            self.client_proto.transport.loseConnection()

class ConnectProxyProtocol(Protocol):
    """
    Handles HTTP CONNECT and tunnels client <-> upstream.
    """
    def __init__(self):
        self._buffer = BytesIO()
        self._tunneled = False
        self.upstream_proto = None

    def dataReceived(self, data: bytes):
        if self._tunneled:
            # Forward to upstream if connected
            if self.upstream_proto and self.upstream_proto.transport:
                self.upstream_proto.transport.write(data)
            else:
                # buffer client data until upstream is ready (bound size)
                if self._buffer.tell() < 64*1024:
                    self._buffer.write(data)
            return

        # Parse CONNECT line
        try:
            text = data.decode("utf-8", errors="ignore")
            first_line = text.splitlines()[0].strip()
            if not first_line.upper().startswith("CONNECT "):
                self.transport.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                self.transport.loseConnection()
                return

            host_port = first_line.split()[1]
            host, port_s = host_port.split(":")
            port = int(port_s)
        except Exception:
            self.transport.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            self.transport.loseConnection()
            return

        logging.info("Proxy CONNECT to %s:%d", host, port)

        # Reply 200 immediately
        self.transport.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunneled = True

        # Buffer any trailing bytes after headers
        hdr_end = data.find(b"\r\n\r\n")
        remaining = b""
        if hdr_end != -1:
            remaining = data[hdr_end+4:]
        else:
            hdr_end = data.find(b"\n\n")
            if hdr_end != -1:
                remaining = data[hdr_end+2:]
        if remaining:
            self._buffer.write(remaining)

        # Connect to upstream
        factory = UpstreamFactory(self, self._buffer)
        try:
            reactor.connectTCP(host, port, factory)
        except Exception:
            try:
                self.transport.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
            self.transport.loseConnection()

    def connectionLost(self, reason):
        # Close upstream if client disconnected
        try:
            if self.upstream_proto and getattr(self.upstream_proto, "transport", None):
                self.upstream_proto.transport.loseConnection()
        except Exception:
            pass
        
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

class ALPNSelector(Protocol):
    """
    Application-layer protocol installed under TLS.  After the TLS handshake
    completes ALPN will be available and we swap in the appropriate handler.
    We schedule the ALPN check on the reactor to avoid racing with the TLS handshake.
    """
    def connectionMade(self):
        # Use ConnectProxyProtocol as permanent handler
        self._fallback = ConnectProxyProtocol()
        self._fallback.factory = getattr(self, "factory", None)
        self.transport.protocol = self._fallback
        self._fallback.makeConnection(self.transport)

        # negotiatedProtocol is the usual attribute Twisted sets after ALPN negotiation.
        negotiated = None
        try:
            negotiated = getattr(self.transport, "negotiatedProtocol", None)
            if callable(negotiated):
                negotiated = negotiated()
        except Exception:
            negotiated = None

        # if negotiated is bytes, decode
        if isinstance(negotiated, bytes):
            negotiated = negotiated

        # Decide which protocol to swap in
        if negotiated == b"h2":
            proto = H2ProxyProtocol(self.transport)
            # H2ProxyProtocol expects transport param in its ctor in your code
        else:
            # Use ConnectProxyProtocol as fallback (e.g. for browsers that will do CONNECT)
            proto = self._fallback   # reuse existing fallback
            proto.factory = getattr(self, "factory", None)

        # Now swap the real protocol in
        try:
            # First, if fallback was installed, try to cleanly disconnect it
            try:
                if hasattr(self, "_fallback") and self._fallback is not None:
                    # give fallback a chance to .connectionLost if it needs to cleanup
                    pass
            except Exception:
                pass

            self.transport.protocol = proto
            if not getattr(proto, "_made_connection", False):
            # Call makeConnection on the new protocol so it sees the transport
                proto._made_connection = True
                proto.makeConnection(self.transport)
        except Exception:
            logger.exception("Failed to swap ALPN protocol")
            try:
                self.transport.loseConnection()
            except Exception:
                pass

        self._swapped = True

    def dataReceived(self, data):
        # Forward directly to the fallback
        self._fallback.dataReceived(data)

# Minimal TLSProtocolWrapper
class TLSProtocolWrapper(TLSMemoryBIOProtocol):
    def __init__(self, protocol, context):
        super().__init__(protocol, context)
        self.wrapped_protocol = protocol

    def connectionMade(self):
        self.wrapped_protocol.makeConnection(self.transport)
        super().connectionMade()

    def dataReceived(self, data):
        self.wrapped_protocol.dataReceived(data)

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
    to the H2 client using StreamMeta.
    Fully streaming: sends data as it arrives instead of waiting for connectionLost.
    """
    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta, encoding: Optional[str] = None):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta
        self.setTimeout(UPSTREAM_TIMEOUT)
        self.encoding = encoding
        self.decompressor = None

        if encoding == "gzip":
            self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            self.decompressor = zlib.decompressobj()

    def dataReceived(self, data: bytes):
        if not data: 
            return
        if self.decompressor:
            data = self.decompressor.decompress(data)
        self.h2_protocol.h2_conn.send_data(self.meta.stream_id, data)
        self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
        incr_bytes_out(len(data))

    def connectionLost(self, reason):
        """
        Upstream closed: flush remaining data and end H2 stream.
        """
        self.meta.closed = True
        # flush all remaining buffered data
        try:
            while chunk := self.meta.pop_chunk(self.h2_protocol.max_frame_size):
                self.h2_protocol.h2_conn.send_data(self.meta.stream_id, chunk)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
                incr_bytes_out(len(chunk))
            # send END_STREAM
            self.h2_protocol.h2_conn.send_data(self.meta.stream_id, b'', end_stream=True)
            self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
        except Exception:
            self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)

    def timeoutConnection(self):
        """
        Upstream timeout: cancel the stream.
        """
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
    def __init__(self, transport):
        self.transport = transport
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

        # Advertise sensible settings immediately
        try:
            self.h2_conn.initiate_connection()
            settings = {
                h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: INITIAL_WINDOW_SIZE_DEFAULT,
                h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: MAX_CONCURRENT_STREAMS_DEFAULT,
                h2.settings.SettingCodes.MAX_FRAME_SIZE: self.max_frame_size
            }
            self.h2_conn.update_settings(settings)
            # Note: data_to_send will be written by wrapper that created this instance
        except Exception:
            pass

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
        self.h2 = H2ProxyProtocol(self.transport)
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
                self.h2_proto = H2ProxyProtocol(self.transport)
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
