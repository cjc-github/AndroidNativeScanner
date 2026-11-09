"""Protocol feature identification from link-level evidence.

The module combines printable strings (protocol keywords such as ``GET``,
``HTTP/``, ``MQTT``, port numbers, message-header constants) with network
imports (``socket``, ``connect``, ``sendto``, ``recvfrom``) to recognise which
network or private protocols a library speaks. Every protocol is identified
independently, each match carries the evidence it was based on, and the
``strength`` field distinguishes single-source matches from corroborated ones
-- stronger, but never a verdict.
"""

from dataclasses import dataclass

__all__ = [
    "ProtocolEvidence",
    "ProtocolHit",
    "ProtocolReport",
    "identify",
    "seed_template",
]


@dataclass(frozen=True)
class ProtocolEvidence:
    """One fingerprint that matched a protocol."""

    source: str
    """Where the evidence came from (``string``, ``symbol``)."""

    detail: str
    """The concrete fingerprint, for the report and the text renderer."""


@dataclass(frozen=True)
class ProtocolHit:
    """A protocol identification, with every fingerprint that matched."""

    protocol: str
    """Stable protocol identifier (``http``, ``tls``, ``mqtt``, ...)."""

    family: str
    """Grouping: ``web``, ``transport``, ``messaging``, ``rpc``, ``media``,
    ``database``, ``iot``, ``vpn``."""

    strength: str
    """``single`` when one source matched, ``corroborated`` for two or more."""

    evidence: tuple[ProtocolEvidence, ...]
    """The fingerprints that hit."""


@dataclass(frozen=True)
class ProtocolReport:
    """The protocols identified in the image."""

    protocols: tuple[ProtocolHit, ...]

    @property
    def corroborated_count(self) -> int:
        return sum(1 for item in self.protocols if item.strength == "corroborated")


def identify(
    string_values: tuple[str, ...],
    symbol_names: tuple[str, ...],
) -> ProtocolReport:
    """Match string and symbol evidence against the protocol table."""
    hits: list[ProtocolHit] = []
    symbol_pool = frozenset(symbol_names)
    for fingerprint in _PROTOCOLS:
        evidence: list[ProtocolEvidence] = []
        for marker in fingerprint.get("strings", ()):
            if any(marker in value for value in string_values):
                evidence.append(ProtocolEvidence("string", marker))
        for symbol in fingerprint.get("symbols", ()):
            if any(name.startswith(symbol) for name in symbol_names):
                evidence.append(ProtocolEvidence("symbol", symbol))
        if not evidence:
            continue
        strength = "corroborated" if len(evidence) >= 2 else "single"
        hits.append(
            ProtocolHit(
                protocol=fingerprint["protocol"],
                family=fingerprint["family"],
                strength=strength,
                evidence=tuple(evidence),
            )
        )
    hits.sort(key=lambda item: (-len(item.evidence), item.protocol))
    return ProtocolReport(protocols=tuple(hits))


_PROTOCOLS: tuple[dict, ...] = (
    {
        "protocol": "http",
        "family": "web",
        "strings": ("HTTP/1.", "HTTP/2", "http://", "GET /", "POST /", "User-Agent:", "Content-Type:"),
        "symbols": (),
    },
    {
        "protocol": "https",
        "family": "web",
        "strings": ("https://", "HTTP/1.1 200", "TLSv1"),
        "symbols": ("SSL_read", "SSL_write", "SSL_connect"),
    },
    {
        "protocol": "tls",
        "family": "transport",
        "strings": ("\x16\x03\x01", "\x16\x03\x03", "TLSv1.2", "TLSv1.3", "SERVER_HELLO"),
        "symbols": ("SSL_CTX_new", "SSL_accept", "tls_clienthello"),
    },
    {
        "protocol": "mqtt",
        "family": "messaging",
        "strings": ("MQTT", "CONNECT\x00", "CONNACK", "PUBLISH", "SUBSCRIBE"),
        "symbols": ("MQTTClient_", "mqtt_"),
    },
    {
        "protocol": "dns",
        "family": "transport",
        "strings": ("\x00\x01\x00\x00\x00\x00\x00\x00", "DNS ", "dns://"),
        "symbols": ("res_query", "res_nquery", "dns_"),
    },
    {
        "protocol": "smtp",
        "family": "web",
        "strings": ("EHLO", "MAIL FROM:", "RCPT TO:", "220 ", "SMTP"),
        "symbols": (),
    },
    {
        "protocol": "ftp",
        "family": "web",
        "strings": ("220 ", "USER ", "PASS ", "SYST", "TYPE I", "FTP"),
        "symbols": (),
    },
    {
        "protocol": "websocket",
        "family": "web",
        "strings": ("Sec-WebSocket-Key", "Sec-WebSocket-Accept", "Upgrade: websocket"),
        "symbols": ("websocket_", "ws_"),
    },
    {
        "protocol": "grpc",
        "family": "rpc",
        "strings": ("grpc", "application/grpc", "grpc-status", "grpc-message"),
        "symbols": ("grpc_", "GRPC_"),
    },
    {
        "protocol": "protobuf",
        "family": "rpc",
        "strings": ("protobuf", "google.protobuf"),
        "symbols": ("google::protobuf", "_ZN6google8protobuf"),
    },
    {
        "protocol": "rtsp",
        "family": "media",
        "strings": ("RTSP/1.0", "rtsp://", "DESCRIBE ", "SETUP ", "PLAY "),
        "symbols": ("rtsp_", "RTSP_"),
    },
    {
        "protocol": "rtmp",
        "family": "media",
        "strings": ("rtmp://", "RTMP", "connect\x00", "FMS"),
        "symbols": ("RTMP_", "rtmp_"),
    },
    {
        "protocol": "websockets",
        "family": "web",
        "strings": ("wss://", "ws://", "Sec-WebSocket-Protocol"),
        "symbols": (),
    },
    {
        "protocol": "postgresql",
        "family": "database",
        "strings": ("PostgreSQL", "PQsetdbLogin", "postgres://", "psql"),
        "symbols": ("PQconnectdb", "PQexec", "PQfinish"),
    },
    {
        "protocol": "mysql",
        "family": "database",
        "strings": ("MySQL", "mysql://", "MariaDB"),
        "symbols": ("mysql_real_connect", "mysql_query", "mysql_close"),
    },
    {
        "protocol": "redis",
        "family": "database",
        "strings": ("redis", "redis://", "REDIS"),
        "symbols": ("redisCommand", "redisConnect", "redisReply"),
    },
    {
        "protocol": "mongodb",
        "family": "database",
        "strings": ("mongodb", "mongodb://", "MongoDB"),
        "symbols": ("mongoc_", "MONGO_"),
    },
    {
        "protocol": "coap",
        "family": "iot",
        "strings": ("\xa0\x01", "COAP", "coap://"),
        "symbols": ("coap_", "COAP_"),
    },
    {
        "protocol": "wireguard",
        "family": "vpn",
        "strings": ("WireGuard", "wireguard"),
        "symbols": ("wg_",),
    },
    {
        "protocol": "openvpn",
        "family": "vpn",
        "strings": ("OpenVPN", "openvpn"),
        "symbols": ("openvpn_",),
    },
    {
        "protocol": "webrtc",
        "family": "media",
        "strings": ("SDP", "ICE", "STUN", "TURN", "webrtc", "candidate:"),
        "symbols": ("peerconnection", "rtc_", "stun_"),
    },
)


#: Minimal, well-formed messages used as fuzz seeds. They are small on purpose:
#: a seed only has to reach the parser, not to be a valid conversation.
_SEED_TEMPLATES = {
    "http": b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: soinsight\r\n\r\n",
    "https": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "websocket": b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    "tls": b"\x16\x03\x01\x00\x50\x01\x00\x00\x4c\x03\x03",
    "dtls": b"\x16\xfe\xfd\x00\x50",
    "dns": b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
    "mqtt": b"\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
    "smtp": b"EHLO soinsight\r\nQUIT\r\n",
    "ftp": b"USER anonymous\r\nPASS soinsight@\r\n",
    "redis": b"*1\r\n$4\r\nPING\r\n",
    "grpc": b"\x00\x00\x00\x00\x00",
    "rtmp": b"connect\x00",
    "rtsp": b"OPTIONS rtsp://localhost/ RTSP/1.0\r\n\r\n",
    "postgresql": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
}


def seed_template(protocol_id: str) -> bytes | None:
    """A minimal message for a known protocol, or ``None`` when unknown.

    The seed generator prefers this over a raw marker string, because a
    well-formed header reaches deeper into the parser than a bare keyword.
    """
    return _SEED_TEMPLATES.get(protocol_id)
