import argparse
import errno
import ipaddress
import json
import os
import select
import socket
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from uping_proto import TYPE_PING, TYPE_PONG, decode_frame, encode_frame
from ustp import USTPReceiver, USTPSender, parse_packet


HELLO_PREFIX = b"USTPS-KEX1\0"
CHALLENGE_PREFIX = b"USTPS-CHALLENGE1\0"
RESPONSE_PREFIX = b"USTPS-CHALLENGE-REPLY1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"
DATA_PORT_PREFIX = b"USTPS-DATA1\0"
UDP_BUFFER_BYTES = 4 * 1024 * 1024
DEFAULT_PORT = 40002


@dataclass
class TransportHandle:
    raw_sock: socket.socket
    usock: AEADDatagramSocket
    peer: tuple
    sender: USTPSender
    receiver: USTPReceiver
    family: int
    label: str
    raw_data_sock: socket.socket | None = None
    data_usock: AEADDatagramSocket | None = None
    ustp2beta_active: bool = False


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def encode_transport_hello(client_pub: bytes, cipher: str, cc_mode: str, cleartext_mode: str, ustp2beta: str) -> bytes:
    return (
        HELLO_PREFIX
        + client_pub
        + cipher.encode("ascii")
        + b"\0cc="
        + cc_mode.encode("ascii")
        + b"\0ct="
        + cleartext_mode.encode("ascii")
        + b"\0u2="
        + ustp2beta.encode("ascii")
    )


def parse_hello_options(raw: bytes) -> tuple[str | None, str | None, str | None, str | None]:
    if not raw:
        return None, None, None, None
    try:
        text = raw.decode("ascii", "replace")
    except Exception:
        return None, None, None, None
    parts = text.split("\0")
    cipher_text = parts[0] if parts else ""
    cipher = None
    if cipher_text:
        try:
            cipher = normalize_cipher_name(cipher_text)
        except Exception:
            cipher = None
    cc_mode = None
    cleartext_mode = None
    ustp2beta = None
    for part in parts[1:]:
        if part.startswith("cc="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cc_mode = value
        elif part.startswith("ct="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cleartext_mode = value
        elif part.startswith("u2="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                ustp2beta = value
    return cipher, cc_mode, cleartext_mode, ustp2beta


def load_tofu(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_tofu(path: str, data: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def check_tofu(path: str, peer_label: str, server_pub: bytes) -> None:
    db = load_tofu(path)
    fp = server_pub.hex()
    known = db.get(peer_label)
    if known is None:
        db[peer_label] = fp
        save_tofu(path, db)
        print(f"[UPING] TOFU trust established for {peer_label}")
        return
    if known != fp:
        raise SystemExit(f"TOFU mismatch for {peer_label}: possible MITM or server key change")


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def bind_udp_socket(bind_ip: str, bind_port: int, family: int) -> socket.socket:
    bind_host = bind_ip
    if family == socket.AF_INET6 and bind_host == "0.0.0.0":
        bind_host = "::"
    if family == socket.AF_INET and bind_host == "::":
        bind_host = "0.0.0.0"
    sock = socket.socket(family, socket.SOCK_DGRAM)
    tune_udp_socket(sock)
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
        sock.bind((bind_host, bind_port, 0, 0))
    else:
        sock.bind((bind_host, bind_port))
    return sock


def resolve_peer_candidates(host: str, port: int, force_family: int | None) -> list[tuple[int, tuple]]:
    normalized = host.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(normalized)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        if force_family is not None and family != force_family:
            return []
        sockaddr = (str(ip), port, 0, 0) if family == socket.AF_INET6 else (str(ip), port)
        return [(family, sockaddr)]
    except ValueError:
        pass
    infos = socket.getaddrinfo(normalized, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    preferred = [socket.AF_INET6, socket.AF_INET] if force_family is None else [force_family]
    out = []
    seen = set()
    for family in preferred:
        for fam, _, _, _, sockaddr in infos:
            if fam != family:
                continue
            key = (fam, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            out.append((fam, sockaddr))
    return out


def family_name(family: int) -> str:
    return "IPv6" if family == socket.AF_INET6 else "IPv4"


def connect_transport(args, selected_cipher: str, client_private, client_pub: bytes, tofu_label: str, force_family: int | None, ustp2beta_mode: str, label: str):
    candidates = resolve_peer_candidates(args.peer_ip, args.peer_port, force_family)
    if not candidates:
        raise SystemExit("no UPing peer candidates")
    last_error = None
    for family, sockaddr in candidates:
        print(f"[UPING][{label}] trying {family_name(family)} {sockaddr[0]}:{sockaddr[1]}")
        raw_candidate = None
        try:
            raw_candidate = bind_udp_socket(args.bind_ip, args.bind_port, family)
            raw_candidate.settimeout(0.2)
            usock_candidate = AEADDatagramSocket(raw_candidate, cipher_name=selected_cipher)
            deadline = time.time() + args.connect_timeout
            challenge_reply_sent = False
            last_hello_ts = 0.0
            while time.time() < deadline:
                now = time.time()
                if not challenge_reply_sent and (now - last_hello_ts) >= 0.2:
                    usock_candidate.send_plain(
                        mkp(
                            TYPE_HELLO,
                            payload=encode_transport_hello(
                                client_pub,
                                selected_cipher,
                                args.congestion_control,
                                args.cleartext,
                                ustp2beta_mode,
                            ),
                        ).to_bytes(),
                        sockaddr,
                    )
                    last_hello_ts = now
                try:
                    raw, addr = usock_candidate.recvfrom(65535)
                except socket.timeout:
                    continue
                pkt = parse_packet(raw)
                if pkt is None or pkt.pkt_type != TYPE_HELLO:
                    continue
                if pkt.payload.startswith(CHALLENGE_PREFIX):
                    rest = pkt.payload[len(CHALLENGE_PREFIX):]
                    parts = rest.split(b"\0", 6)
                    if len(parts) != 7 or len(parts[6]) != 32:
                        continue
                    token = parts[0].decode("ascii", "replace")
                    session_id = parts[1].decode("ascii", "replace")
                    session_cipher, negotiated_cc, negotiated_cleartext, negotiated_u2 = parse_hello_options(
                        parts[2] + b"\0" + parts[3] + b"\0" + parts[4] + b"\0" + parts[5]
                    )
                    session_cipher = session_cipher or selected_cipher
                    server_pub = parts[6]
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    if negotiated_cc != args.congestion_control:
                        raise SystemExit(
                            f"server negotiated unexpected congestion control mode {negotiated_cc}; expected {args.congestion_control}"
                        )
                    if negotiated_cleartext != args.cleartext:
                        raise SystemExit(
                            f"server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}"
                        )
                    if negotiated_u2 not in ("on", "off"):
                        raise SystemExit(f"server negotiated invalid ustp2beta mode {negotiated_u2}")
                    if ustp2beta_mode == "on" and negotiated_u2 != "on":
                        raise SystemExit("server negotiated unexpected ustp2beta mode off; expected on")
                    check_tofu(args.tofu_file, tofu_label, server_pub)
                    reply = (
                        RESPONSE_PREFIX
                        + token.encode("ascii")
                        + b"\0"
                        + session_id.encode("ascii")
                        + b"\0"
                        + session_cipher.encode("ascii")
                        + b"\0cc="
                        + negotiated_cc.encode("ascii")
                        + b"\0ct="
                        + negotiated_cleartext.encode("ascii")
                        + b"\0u2="
                        + negotiated_u2.encode("ascii")
                        + b"\0"
                        + client_pub
                    )
                    usock_candidate.send_plain(mkp(TYPE_HELLO, payload=reply).to_bytes(), addr)
                    challenge_reply_sent = True
                    continue
                if pkt.payload.startswith(SESSION_PREFIX):
                    rest = pkt.payload[len(SESSION_PREFIX):]
                    parts = rest.split(b"\0", 5)
                    if len(parts) != 6 or len(parts[5]) != 32:
                        continue
                    session_cipher, negotiated_cc, negotiated_cleartext, negotiated_u2 = parse_hello_options(
                        parts[1] + b"\0" + parts[2] + b"\0" + parts[3] + b"\0" + parts[4]
                    )
                    session_cipher = session_cipher or selected_cipher
                    server_pub = parts[5]
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    if negotiated_cc != args.congestion_control:
                        raise SystemExit(
                            f"server negotiated unexpected congestion control mode {negotiated_cc}; expected {args.congestion_control}"
                        )
                    if negotiated_cleartext != args.cleartext:
                        raise SystemExit(
                            f"server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}"
                        )
                    if negotiated_u2 not in ("on", "off"):
                        raise SystemExit(f"server negotiated invalid ustp2beta mode {negotiated_u2}")
                    check_tofu(args.tofu_file, tofu_label, server_pub)
                    server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                    session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                    usock_candidate.set_peer_psk(
                        addr,
                        session_key,
                        session_cipher,
                        cleartext=(negotiated_cleartext == "on"),
                    )
                    raw_data_candidate = None
                    data_usock_candidate = None
                    if negotiated_u2 == "on":
                        raw_data_candidate = bind_udp_socket(args.bind_ip, args.bind_port, family)
                        raw_data_candidate.settimeout(0.2)
                        data_usock_candidate = AEADDatagramSocket(raw_data_candidate, cipher_name=selected_cipher)
                        data_usock_candidate.set_peer_psk(
                            addr,
                            session_key,
                            session_cipher,
                            cleartext=(negotiated_cleartext == "on"),
                        )
                        for _ in range(3):
                            data_usock_candidate.send_plain(
                                mkp(TYPE_HELLO, payload=DATA_PORT_PREFIX + parts[0]).to_bytes(),
                                addr,
                            )
                    sender_candidate = USTPSender(
                        sock=usock_candidate,
                        peer=addr,
                        window=256,
                        rto=0.25,
                        max_burst=256,
                        pump_interval=0.001,
                        congestion_control=(negotiated_cc == "on"),
                    )
                    sender_candidate.start()
                    receiver_candidate = USTPReceiver(sock=usock_candidate, peer=addr)
                    print(f"[UPING][{label}] connected via {family_name(family)} local={raw_candidate.getsockname()} peer={addr[0]}:{addr[1]} ustp2beta={negotiated_u2}")
                    return TransportHandle(
                        raw_sock=raw_candidate,
                        usock=usock_candidate,
                        peer=addr,
                        sender=sender_candidate,
                        receiver=receiver_candidate,
                        family=family,
                        label=label,
                        raw_data_sock=raw_data_candidate,
                        data_usock=data_usock_candidate,
                        ustp2beta_active=(negotiated_u2 == "on"),
                    )
            raise TimeoutError(f"{family_name(family)} handshake timed out")
        except Exception as exc:
            last_error = exc
            print(f"[UPING][{label}] {family_name(family)} failed: {exc}")
            if raw_candidate is not None:
                try:
                    raw_candidate.close()
                except Exception:
                    pass
    if last_error is not None:
        raise last_error
    raise SystemExit("UPing connection failed")


def close_transport(handle: TransportHandle) -> None:
    try:
        if handle.usock is not None and handle.peer is not None:
            handle.usock.send_plain(mkp(TYPE_CLOSE, payload=b"BYE").to_bytes(), handle.peer)
    except Exception:
        pass
    try:
        if handle.sender is not None:
            handle.sender.stop()
        if handle.raw_sock is not None:
            handle.raw_sock.close()
        if handle.raw_data_sock is not None and handle.raw_data_sock is not handle.raw_sock:
            handle.raw_data_sock.close()
    except Exception:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="UPing: USTPS ping")
    ap.add_argument("--peer-ip", required=True, help="Server hostname or IP")
    ap.add_argument("--peer-port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=0)
    ap.add_argument("--count", "-c", type=int, default=0, help="Number of pings, 0 = infinite")
    ap.add_argument("--interval", "-i", type=float, default=1.0, help="Seconds between pings")
    ap.add_argument("--timeout", "-W", type=float, default=3.0, help="Per-ping timeout in seconds")
    ap.add_argument("--connect-timeout", type=float, default=6.0, help="USTPS handshake timeout per family")
    ap.add_argument("--size", "-s", type=int, default=56, help="Ping payload size")
    ap.add_argument("--cipher", default="chacha20", help="chacha20 | aes-256-gcm | aes-128-gcm")
    ap.add_argument(
        "--congestion-control",
        choices=("on", "off"),
        default="off",
        help="Request USTPS congestion control on or off",
    )
    ap.add_argument(
        "--cleartext",
        choices=("on", "off"),
        default="off",
        help="Request USTPS cleartext + HMAC mode for DATA",
    )
    ap.add_argument("--ustp2beta", choices=("on", "off"), default="off", help="Enable USTP/2 Beta split data/control sockets")
    ap.add_argument(
        "--test-ustp2beta-and-ustp1.1-simultaneously",
        dest="test_ustp2beta_and_ustp11_simultaneously",
        action="store_true",
        help="Open one USTP/1.1 session and one USTP/2 Beta session at the same time for comparison",
    )
    ap.add_argument("--tofu-file", default=os.path.expanduser("~/.uping_known_hosts.json"))
    ap.add_argument("-4", dest="force_ipv4", action="store_true", help="Force IPv4")
    ap.add_argument("-6", dest="force_ipv6", action="store_true", help="Force IPv6")
    args = ap.parse_args()

    if args.force_ipv4 and args.force_ipv6:
        raise SystemExit("use only one of -4 or -6")

    force_family = None
    if args.force_ipv4:
        force_family = socket.AF_INET
    elif args.force_ipv6:
        force_family = socket.AF_INET6

    selected_cipher = normalize_cipher_name(args.cipher)
    tofu_label = f"{args.peer_ip}:{args.peer_port}"
    client_private = x25519.X25519PrivateKey.generate()
    client_pub = public_bytes(client_private.public_key())

    if args.test_ustp2beta_and_ustp11_simultaneously:
        modes = [("ustp1.1", "off"), ("ustp2beta", "on")]
    else:
        modes = [("ustp2beta" if args.ustp2beta == "on" else "ustp1.1", args.ustp2beta)]

    transports: list[TransportHandle] = []
    stats: dict[str, dict[str, object]] = {}
    try:
        for label, u2_mode in modes:
            client_private_mode = x25519.X25519PrivateKey.generate()
            client_pub_mode = public_bytes(client_private_mode.public_key())
            handle = connect_transport(
                args,
                selected_cipher,
                client_private_mode,
                client_pub_mode,
                tofu_label,
                force_family,
                u2_mode,
                label,
            )
            transports.append(handle)
            remote_family = "IPv6" if ":" in handle.peer[0] else "IPv4"
            print(f"UPING[{label}] {args.peer_ip} ({handle.peer[0]}) over USTPS: {args.size} data bytes, port {args.peer_port}, {remote_family}")
            stats[label] = {"sent": 0, "received": 0, "rtts": []}

        seq = 0
        payload = b"Q" * max(0, args.size)
        try:
            while args.count == 0 or seq < args.count:
                seq += 1
                for handle in transports:
                    sent_ns = time.monotonic_ns()
                    frame = encode_frame(TYPE_PING, 1, seq, sent_ns, payload)
                    handle.sender.queue_payload(frame)
                    stats[handle.label]["sent"] = int(stats[handle.label]["sent"]) + 1
                    deadline = time.time() + args.timeout
                    got_reply = False
                    while time.time() < deadline:
                        try:
                            if handle.ustp2beta_active and handle.data_usock is not None:
                                readable, _, _ = select.select(
                                    [handle.raw_sock, handle.raw_data_sock],
                                    [],
                                    [],
                                    min(0.2, max(0.0, deadline - time.time())),
                                )
                                if not readable:
                                    continue
                                # Drain control first so ACKs cannot starve behind
                                # a continuous stream of USTP/2 DATA packets.
                                if handle.raw_sock in readable:
                                    raw, _addr = handle.usock.recvfrom(65535)
                                else:
                                    raw, _addr = handle.data_usock.recvfrom(65535)
                            else:
                                raw, _addr = handle.usock.recvfrom(65535)
                        except socket.timeout:
                            continue
                        pkt = parse_packet(raw)
                        if pkt is None:
                            continue
                        if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST):
                            handle.sender.on_control(pkt)
                            continue
                        if pkt.pkt_type == TYPE_CLOSE:
                            raise SystemExit(f"server closed the UPing session ({handle.label})")
                        if pkt.pkt_type != TYPE_DATA:
                            continue
                        app_payload = handle.receiver.handle_data(pkt)
                        handle.receiver.maybe_nack()
                        if not app_payload:
                            continue
                        reply = decode_frame(app_payload)
                        if reply is None or reply["type"] != TYPE_PONG or reply["seq"] != seq:
                            continue
                        rtt_ms = (time.monotonic_ns() - reply["sent_ns"]) / 1_000_000.0
                        stats[handle.label]["received"] = int(stats[handle.label]["received"]) + 1
                        cast_rtts = stats[handle.label]["rtts"]
                        assert isinstance(cast_rtts, list)
                        cast_rtts.append(rtt_ms)
                        remote_family = "IPv6" if ":" in handle.peer[0] else "IPv4"
                        print(
                            f"[{handle.label}] {len(reply['payload'])} bytes from {handle.peer[0]}:{handle.peer[1]}: "
                            f"up_seq={seq} time={rtt_ms:.2f} ms family={remote_family}"
                        )
                        got_reply = True
                        break
                    if not got_reply:
                        print(f"[{handle.label}] Request timeout for up_seq={seq}")
                if args.count == 0 or seq < args.count:
                    time.sleep(max(0.0, args.interval))
        except KeyboardInterrupt:
            pass
    finally:
        for handle in transports:
            close_transport(handle)

    for handle in transports:
        label_stats = stats[handle.label]
        sent = int(label_stats["sent"])
        received = int(label_stats["received"])
        rtts = label_stats["rtts"]
        assert isinstance(rtts, list)
        loss = ((sent - received) / sent * 100.0) if sent else 0.0
        receiver_stats = handle.receiver.get_stats()
        sender_stats = handle.sender.get_stats()
        receiver_gave_up = max(sent - received, receiver_stats["abandoned_packets"])
        print(f"\n--- {args.peer_ip} UPing statistics [{handle.label}] ---")
        print(
            f"{sent} packets transmitted, {received} received, {loss:.1f}% packet loss "
            f"({receiver_gave_up} packets abandoned by receiver)"
        )
        recovered = receiver_stats["recovered_packets"] + int(sender_stats["recovered_packets"])
        print(f"{recovered} transport packets lost but recovered by retransmission")
        if rtts:
            print(f"rtt min/avg/max = {min(rtts):.2f}/{(sum(rtts)/len(rtts)):.2f}/{max(rtts):.2f} ms")


if __name__ == "__main__":
    main()
