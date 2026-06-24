"""TLS key-exchange detection for the /classify endpoint.

This is the project's original pyshark implementation from
Filter_algorithm_for_protocols/filter_tls_packets.py (key_share key-exchange
length matched against the algorithm size tables), adapted only so that results
are returned as structured data instead of printed to ./out/*.txt.

Requires tshark (Wireshark CLI) on PATH, which pyshark drives.

Entry point: ``classify(pcap_path) -> [{"ip", "algorithms"}]``.
"""
import hashlib
import os
import shutil

import pyshark

pq_algorithms = {
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

classical_algorithms = {
    "RSA-2048": 256, "RSA-3072": 384, "RSA-4096": 512,
    "ECDH-P256": 65, "ECDH-P384": 97, "ECDH-P521": 133,
    "X25519": 32, "X448": 56,
    "DH-2048": 256, "DH-3072": 384, "DH-4096": 512, "DH-8192": 1024,
}

TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1
TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2
TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16
TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12


def _simple_hash(elements):
    return hashlib.sha256("".join(str(e) for e in elements).encode()).hexdigest()


def _check_classical(packet_size):
    out = []
    for key, val in classical_algorithms.items():
        if val - 5 < packet_size < val + 5:
            out.append(key)
    return out


def _check_quantum(packet_size, pk=1):
    out = []
    idx = 0 if pk else 1
    for key, sizes in pq_algorithms.items():
        if sizes[idx] - 5 < packet_size < sizes[idx] + 5:
            out.append(key)
    return out


def _check_hybrid(packet_size, pk=1):
    out = []
    idx = 0 if pk else 1
    for key_c, val in classical_algorithms.items():
        for key_q, sizes in pq_algorithms.items():
            if sizes[idx] - 5 < (packet_size - val) < sizes[idx] + 5:
                out.append(key_c + " + " + key_q)
    return out


def _classify_pair(init_packet, reply_packet):
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
    algos = []
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


def classify(pcap_path, tshark_path=None):
    """Detect TLS 1.3 key exchange per connection. Returns [{"ip","algorithms"}]."""
    tshark_path = tshark_path or shutil.which("tshark") or "/opt/homebrew/bin/tshark"
    packets = {}  # hash -> (clienthello, serverhello)

    capture = pyshark.FileCapture(
        pcap_path,
        tshark_path=tshark_path,
        display_filter=(
            f"(tls.handshake.type == {TLS_HANDSHAKE_TYPE_CLIENT_HELLO} or "
            f"tls.handshake.type == {TLS_HANDSHAKE_TYPE_SERVER_HELLO} or "
            f"tls.handshake.type == {TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE} or "
            f"tls.handshake.type == {TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE})"
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

            if handshake_type == TLS_HANDSHAKE_TYPE_SERVER_HELLO:
                if hasattr(tls, "handshake_extensions_supported_version") and \
                        "304" in tls.handshake_extensions_supported_version:
                    try:
                        sid = tls.handshake_session_id
                    except AttributeError:
                        sid = ""
                    key = _simple_hash([ip_dst, ip_src, transport.dstport, transport.srcport, sid])
                    v1, _ = packets.get(key, (None, None))
                    packets[key] = (v1, packet)
            elif handshake_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
                if hasattr(tls, "handshake_extensions_supported_version") and \
                        "304" in tls.handshake_extensions_supported_version:
                    try:
                        sid = tls.handshake_session_id
                    except AttributeError:
                        sid = ""
                    key = _simple_hash([ip_src, ip_dst, transport.srcport, transport.dstport, sid])
                    _, v2 = packets.get(key, (None, None))
                    packets[key] = (packet, v2)
    finally:
        capture.close()

    results, seen = [], set()
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


if __name__ == "__main__":
    import sys, json
    # Emit only JSON on stdout so the /classify endpoint can parse it directly.
    out = classify(sys.argv[1])
    sys.stdout.write(json.dumps(out))
