"""TLS capture classifier — detect (post-quantum) key exchange in a .pcapng.

This is the package counterpart of the web app's ``/classify`` endpoint. It
ports the project's original pyshark logic (read the TLS 1.3 key_share group /
key-exchange length from the ServerHello and match it against the algorithm
size tables). Unlike the kex/sig classifiers it needs no model or scaler — the
algorithm is inferred directly from handshake sizes.

``pyshark`` (and the system ``tshark`` binary it drives) is an optional
dependency: install it with ``pip install pq_classification[capture]`` and a
system tshark (e.g. ``brew install wireshark`` / ``apt install tshark``). It is
imported lazily so ``import pq_classification`` works without it.
"""

from __future__ import annotations

import hashlib
import shutil
from typing import Optional

pq_algorithms: dict[str, tuple[int, int]] = {
    # Post-Quantum Algorithms   (public-key size, ciphertext size)
    "Classic-McEliece-348864": (261120, 96),
    "Classic-McEliece-460896": (524160, 156),
    "Classic-McEliece-6688128": (1044992, 208),
    "Classic-McEliece-6960119": (1047319, 194),
    "Classic-McEliece-8192128": (1357824, 208),
    "BIKE-L1": (1541, 1573),
    "BIKE-L3": (3083, 3115),
    "BIKE-L5": (5122, 5154),
    "Kyber512": (800, 768),
    "Kyber768": (1184, 1088),
    "Kyber1024": (1568, 1568),
    "FrodoKEM-640": (9616, 9720),
    "FrodoKEM-976": (15632, 15744),
    "FrodoKEM-1344": (21520, 21632),
    "HQC-128": (2249, 4433),
    "HQC-192": (4522, 8978),
    "HQC-256": (7245, 14421),
    "SNTRUP761": (1158, 1039),
}

classical_algorithms: dict[str, int] = {
    "RSA-2048": 256, "RSA-3072": 384, "RSA-4096": 512,
    "ECDH-P256": 65, "ECDH-P384": 97, "ECDH-P521": 133,
    "X25519": 32, "X448": 56,
    "DH-2048": 256, "DH-3072": 384, "DH-4096": 512, "DH-8192": 1024,
}

_CLIENT_HELLO = 1
_SERVER_HELLO = 2
_CLIENT_KEY_EXCHANGE = 16
_SERVER_KEY_EXCHANGE = 12


def _simple_hash(elements) -> str:
    return hashlib.sha256("".join(str(e) for e in elements).encode()).hexdigest()


def _check_classical(size: int) -> list[str]:
    return [k for k, v in classical_algorithms.items() if v - 5 < size < v + 5]


def _check_quantum(size: int, pk: int = 1) -> list[str]:
    idx = 0 if pk else 1
    return [k for k, s in pq_algorithms.items() if s[idx] - 5 < size < s[idx] + 5]


def _check_hybrid(size: int, pk: int = 1) -> list[str]:
    idx = 0 if pk else 1
    out: list[str] = []
    for kc, vc in classical_algorithms.items():
        for kq, sq in pq_algorithms.items():
            if sq[idx] - 5 < (size - vc) < sq[idx] + 5:
                out.append(kc + " + " + kq)
    return out


def _classify_pair(init_packet, reply_packet) -> tuple[str, list[str]]:
    """Return (server_ip, [algorithms]) for one ClientHello/ServerHello pair."""
    ver_attr = "handshake_extensions_supported_version"
    len_attr = "handshake_extensions_key_share_key_exchange_length"

    tls_init = init_packet["tls"] if init_packet is not None else None
    tls_reply = reply_packet["tls"]
    ip_reply = reply_packet.ipv6 if "ipv6" in reply_packet else reply_packet.ip

    c_init = q_init = h_init = []
    c_reply = q_reply = h_reply = []

    if tls_init is not None and hasattr(tls_init, ver_attr) and "304" in getattr(tls_init, ver_attr):
        if hasattr(tls_init, len_attr):
            n = int(getattr(tls_init, len_attr))
            c_init, q_init, h_init = _check_classical(n), _check_quantum(n), _check_hybrid(n)

    if hasattr(tls_reply, ver_attr) and "304" in getattr(tls_reply, ver_attr):
        if hasattr(tls_reply, len_attr):
            n = int(getattr(tls_reply, len_attr))
            c_reply, q_reply, h_reply = _check_classical(n), _check_quantum(n, 0), _check_hybrid(n, 0)

    # Same priority resolution as the original: classical, then quantum, then hybrid.
    algos: list[str] = []
    priority = 0
    if c_init and c_reply and c_init == c_reply:
        algos = c_init; priority = 1
    elif c_reply:
        algos = c_reply
    elif c_init:
        algos = c_init

    if priority == 0 and not algos:
        if q_init and q_reply and q_init == q_reply:
            algos = q_init
        elif q_reply:
            algos = q_reply
        elif q_init:
            algos = q_init

    if priority == 0 and not algos:
        if h_init and h_reply and h_init == h_reply:
            algos = h_init
        elif h_reply:
            algos = h_reply
        elif h_init:
            algos = h_init

    # The original drops bare X448 matches as noise.
    algos = [a for a in algos if a.strip() != "X448"]
    return ip_reply.src, algos


def classify(pcap_path, tshark_path: Optional[str] = None) -> list[dict]:
    """Detect TLS 1.3 key exchange per connection in a ``.pcapng``.

    Parameters
    ----------
    pcap_path : str | pathlib.Path
        Path to the capture file.
    tshark_path : str, optional
        Explicit path to the ``tshark`` binary; auto-detected on PATH if omitted.

    Returns
    -------
    list[dict]
        ``[{"ip": server_ip, "algorithms": [..]}, ...]`` for detected handshakes.
    """
    try:
        import pyshark
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "pyshark is required for capture classification — "
            "install with: pip install pq_classification[capture]"
        ) from exc

    tshark_path = tshark_path or shutil.which("tshark")
    packets: dict[str, tuple] = {}

    capture = pyshark.FileCapture(
        str(pcap_path),
        tshark_path=tshark_path,
        display_filter=(
            f"(tls.handshake.type == {_CLIENT_HELLO} or "
            f"tls.handshake.type == {_SERVER_HELLO} or "
            f"tls.handshake.type == {_CLIENT_KEY_EXCHANGE} or "
            f"tls.handshake.type == {_SERVER_KEY_EXCHANGE})"
        ),
    )
    try:
        for packet in capture:
            if not hasattr(packet, "tls"):
                continue
            tls = packet["tls"]
            transport = packet["tcp"] if hasattr(packet, "tcp") else packet["udp"]
            try:
                handshake_type = int(packet.tls.handshake_type)
            except AttributeError:
                continue
            if "ipv6" in packet:
                ip_src, ip_dst = packet.ipv6.src, packet.ipv6.dst
            elif "ip" in packet:
                ip_src, ip_dst = packet.ip.src, packet.ip.dst
            else:
                continue

            if handshake_type == _SERVER_HELLO:
                if hasattr(tls, "handshake_extensions_supported_version") and \
                        "304" in tls.handshake_extensions_supported_version:
                    sid = getattr(tls, "handshake_session_id", "")
                    key = _simple_hash([ip_dst, ip_src, transport.dstport, transport.srcport, sid])
                    v1, _ = packets.get(key, (None, None))
                    packets[key] = (v1, packet)
            elif handshake_type == _CLIENT_HELLO:
                if hasattr(tls, "handshake_extensions_supported_version") and \
                        "304" in tls.handshake_extensions_supported_version:
                    sid = getattr(tls, "handshake_session_id", "")
                    key = _simple_hash([ip_src, ip_dst, transport.srcport, transport.dstport, sid])
                    _, v2 = packets.get(key, (None, None))
                    packets[key] = (packet, v2)
    finally:
        capture.close()

    results: list[dict] = []
    seen: set = set()
    for v1, v2 in packets.values():
        if v2 is None:
            continue
        ip, algos = _classify_pair(v1, v2)
        if not algos:
            continue
        dedup = (ip, tuple(algos))
        if dedup in seen:
            continue
        seen.add(dedup)
        results.append({"ip": ip, "algorithms": algos})
    return results
