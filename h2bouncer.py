#!/usr/bin/env python3
# Hardened HTTP/2 -> HTTP/1.1 streaming proxy
# RFC 7540 compliant with Cloudflare IP whitelisting, metrics, and diagnostics

from __future__ import annotations
import sys, time, logging, signal, ipaddress, subprocess, urllib.parse
from typing import Dict, List, Optional, Tuple, Set

from twisted.internet import reactor, task, defer, ssl as tssl, endpoints
from twisted.internet.threads import deferToThread
from twisted.internet.protocol import Protocol, Factory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.internet.defer import Deferred
from twisted.protocols.policies import TimeoutMixin
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource
from twisted.web.client import FileBodyProducer
from io import BytesIO

import h2.connection
import h2.events
import h2.config
import h2.settings
import h2.errors

from OpenSSL import SSL
#import ssl as pyssl
import urllib.request
from collections import deque
import socket
from urllib.parse import urlparse
import re
import zlib

# ---------- Configuration ----------
LISTEN_PORT = 8080
IP_REFRESH_INTERVAL = 3600

CERT_FILE = "/home/user/Documents/CERTS/cert.pem"
KEY_FILE = "/home/user/Documents/CERTS/key.pem"

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
        if not data:
            return
        if self.buffered_bytes + len(data) > MAX_BUFFER_PER_STREAM:
            logger.warning("Stream %d buffer exceeded %d bytes, resetting",
                           self.stream_id, MAX_BUFFER_PER_STREAM)
            self.reset_stream(h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
            return
        # Break into fixed-size chunks
        for i in range(0, len(data), self.CHUNK_SIZE):
            chunk = memoryview(data[i:i+self.CHUNK_SIZE])
            self.chunks.append(chunk)
            self.buffered_bytes += len(chunk)
        self.last_activity = time.time()
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
        # Use original hostname for HTTPS (SNI correct)
        agent = self.agent_https if parsed.scheme=="https" else self.agent_http
        hdrs = Headers()
        for k,v in self.headers:
            hdrs.addRawHeader(k.encode(), v.encode())
        # Ensure Host header
        if not any(k.lower()=="host" for k,_ in self.headers):
            hdrs.addRawHeader(b"host", parsed.netloc.encode())

        # prepare body for upstream request if any
        body_data = b''.join(self.meta.chunks) if self.meta.chunks else None
        body_producer = FileBodyProducer(BytesIO(body_data)) if body_data else None

        d = agent.request(self.method, self.url.encode(), headers=hdrs, bodyProducer=body_producer)


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
                if lname in ("connection","proxy-connection","keep-alive","transfer-encoding","upgrade","te","alt-svc"):
                    continue
                if lname == "content-encoding":
                    encoding = val.lower()
                    continue
                h2_headers.append((lname, val))

            # Hardened defaults
            if not any(k.lower()=="x-content-type-options" for k,_ in h2_headers):
                h2_headers.append(("x-content-type-options","nosniff"))
            if not any(k.lower()=="referrer-policy" for k,_ in h2_headers):
                h2_headers.append(("referrer-policy","no-referrer"))

            # Send headers immediately
            try:
                self.h2_protocol.h2_conn.send_headers(self.meta.stream_id, h2_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception:
                pass

            # Deliver body to our receiver
            receiver = UpstreamStreamReceiver(self.h2_protocol, self.meta, encoding=encoding)
            resp.deliverBody(receiver)

            # **No on_done() callback needed anymore**  
            # The receiver will handle flushing and end_stream in connectionLost()
            return resp

        def on_error(f):
            if timeout_call.active(): timeout_call.cancel()
            if self.meta.closed: return
            if f.check(defer.CancelledError):
                logger.warning("Upstream fetch cancelled for stream %d", self.meta.stream_id)
                self.meta.reset_stream(h2.errors.ErrorCodes.CANCEL)
                return
            if attempt < self.MAX_RETRIES:
                logger.warning("Upstream fetch failed, retry %d/%d: %s",
                               attempt, self.MAX_RETRIES, f)
                reactor.callLater(self.RETRY_DELAY, lambda: self.start(attempt+1))
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
# H2 protocol implementation (server-side)
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
        try:
            if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                self._idle_call.cancel()
        except Exception:
            pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # Normalize headers to lowercase text
        headers: List[Tuple[str, str]] = []
        for k, v in event.headers:
            key = k.decode() if isinstance(k, bytes) else k
            val = v.decode() if isinstance(v, bytes) else v
            headers.append((key.lower(), val))

        method = next((v for (k, v) in headers if k == ":method"), None)
        path = next((v for (k, v) in headers if k == ":path"), None)
        scheme = next((v for (k, v) in headers if k == ":scheme"), None)
        authority = next((v for (k, v) in headers if k == ":authority"), None)

        # RFC 7540 §8.1.2.3 pseudo-headers
        if not method or not path or not scheme or not authority:
            try:
                self.h2_conn.reset_stream(event.stream_id, error_code=int(h2.errors.ErrorCodes.PROTOCOL_ERROR))
                self.transport.write(self.h2_conn.data_to_send())
            except Exception:
                pass
            return
        
        # allow all methods (GET, HEAD, POST, PUT, PATCH, etc.)
        #if method.upper() not in ("GET", "HEAD"):
        #    try:
        #        hdrs = [(":status", "405"), ("content-length", "0")]
        #        self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
        #        self.transport.write(self.h2_conn.data_to_send())
        #        incr_streams_reset()
        #    except Exception:
        #        pass
        #    return

        # Concurrency guard
        if len(self.stream_meta) >= self.max_concurrent_streams:
            try:
                hdrs = [(":status", "503"), ("content-length", "0")]
                self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
                incr_streams_reset()
            except Exception:
                pass
            return

        # Normalize absolute URL
        if path.startswith("/") and re.match(r"^https?://", path[1:], re.IGNORECASE):
            absolute_url = path[1:] #Ex.: curl -v --http2 --insecure https://localhost:8080/https://www.google.com/
        elif re.match(r"^https?://", path, re.IGNORECASE):
            absolute_url = path
        else:
            absolute_url = f"{scheme}://{authority}{path}"

        parsed = urlparse(absolute_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            try:
                hdrs = [(":status", "400"), ("content-length", "0")]
                self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
            except Exception:
                pass
            return

        # SSRF guard: resolve all targets & block private ranges
        try:
            host_only = parsed.hostname or ""
            enforce_ssrf_guard(host_only)
        except Exception as e:
            logger.warning("SSRF guard blocked request to %s: %s", path, e)
            try:
                hdrs = [(":status", "403"), ("content-length", "0")]
                self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
            except Exception:
                pass
            return

        meta = StreamMeta(event.stream_id, self, method=method)
        self.stream_meta[event.stream_id] = meta
        safe_increment("active_streams", 1)

        # Filter out :pseudo headers and Host
        upstream_headers = [
            (k, v) for (k, v) in headers
            if not k.startswith(":") and k.lower() != "host"
        ]

        # Explicitly set correct Host header for upstream
        upstream_headers.append(("host", parsed.netloc))


        # Ensure Accept-Encoding present (Agent will handle decompression if needed)
        if not any(k == "accept-encoding" for (k, _v) in upstream_headers):
            upstream_headers.append(("accept-encoding", "gzip, deflate"))

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

            #elif isinstance(event, h2.events.SettingsReceived):
            #    # MUST ack peer settings (RFC 7540 §6.5.3)
            #    try:
            #        # newer h2 versions use: self.h2_conn.acknowledge_settings()
            #        # some accept the event; try both defensively
            #        try:
            #            self.h2_conn.acknowledge_settings(event)
            #        except TypeError:
            #            # fallback: call without args
            #            self.h2_conn.acknowledge_settings()
            #        self.transport.write(self.h2_conn.data_to_send())
            #    except Exception:
            #        pass

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
        # mark sending active
        if getattr(self, "_sending_loop_active", False):
            return
        self._sending_loop_active = True

        try:
            any_sent = False
            for meta in self.stream_meta.values():
                if meta.closed or meta.buffered_bytes <= 0:
                    continue

                while chunk := meta.pop_chunk(self.max_frame_size):
                    try:
                        self.h2_conn.send_data(meta.stream_id, chunk)
                        self.transport.write(self.h2_conn.data_to_send())
                        incr_bytes_out(len(chunk))
                        any_sent = True
                    except Exception:
                        meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)

        finally:
            self._sending_loop_active = False
            # schedule next tick if there is remaining buffered data
            if any(meta.buffered_bytes > 0 for meta in self.stream_meta.values()):
                reactor.callLater(0.01, self._send_loop)



    def initiate_push(self, parent_stream_id: int, link_path: str):
        # disabled for safety
        #parsed = urllib.parse.urlparse(link_path)
        #path = parsed.path or "/"
        #if parsed.query:
        #    path += "?" + parsed.query

        #if parsed.netloc and parsed.netloc.split(':', 1)[0] != UPSTREAM_HOST:
        #    logger.debug("Refusing to push cross-origin resource: %s", link_path)
        #    return

        #try:
        #    sid = self.h2_conn.get_next_available_stream_id()
        #    headers = [(":method", "GET"), (":path", path), (":scheme", "https"),
        #               (":authority", parsed.netloc or UPSTREAM_HOST)]
        #    self.h2_conn.push_stream(parent_stream_id, sid, headers)
        #    self.transport.write(self.h2_conn.data_to_send())
        #except Exception as e:
        #    logger.debug("Push failed for %s: %s", path, e)
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
        except Exception:
            pass

    def dataReceived(self, data):
        self.h2.dataReceived(data)

class H2Factory(Factory):
    def buildProtocol(self, addr):
        return H2ProtocolWrapper()
    
class ALPNContextFactory(tssl.DefaultOpenSSLContextFactory):
    """
    Twisted-compatible SSL context factory with ALPN for HTTP/2.
    """
    def __init__(self, privateKeyFileName, certificateFileName):
        super().__init__(privateKeyFileName, certificateFileName)

    def getContext(self):
        ctx = super().getContext()
        ctx.set_options(SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)  # optional: only TLSv1.2+
        
        # ALPN callback
        def select_alpn(conn, protos):
            # protos is a list of bytes offered by the client
            if b"h2" in protos:
                return b"h2"
            if b"http/1.1" in protos:
                return b"http/1.1"
            return protos[0]  # fallback to first offered

        ctx.set_alpn_select_callback(select_alpn)
        return ctx

def start_tls_listener():
    factory = H2Factory()  # your H2Protocol factory
    ctx_factory = ALPNContextFactory(KEY_FILE, CERT_FILE)
    endpoint = endpoints.SSL4ServerEndpoint(reactor, LISTEN_PORT, ctx_factory)
    endpoint.listen(factory)
    logger.info(f"TLS listener started on port {LISTEN_PORT} (HTTP/2 enabled)")


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
    reactor.run()
