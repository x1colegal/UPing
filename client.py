import argparse
import base64
import errno
import ipaddress
import json
import os
import socket
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from uping_proto import TYPE_PING, TYPE_PONG, decode_frame, encode_frame
from ustp import USTPReceiver, USTPSender, parse_packet


HELLO_PREFIX = b"USTPS-KEX1 "
CHALLENGE_PREFIX = b"USTPS-CHALLENGE1 "
RESPONSE_PREFIX = b"USTPS-CHALLENGE-REPLY1 "
SESSION_PREFIX = b"USTPS-SESSION1 "
UDP_BUFFER_BYTES = 4 * 1024 * 1024
DEFAULT_PORT = 40002


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    padded = text + ("=" * (-len(text) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def encode_ascii_record(prefix: bytes, **fields: str) -> bytes:
    parts = [prefix.rstrip()]
    for key, value in fields.items():
        parts.append(f"{key}={value}".encode("ascii"))
    return b" ".join(parts)


def parse_ascii_record(payload: bytes, prefix: bytes) -> dict[str, str] | None:
    if not payload.startswith(prefix):
        return None
    try:
        text = payload[len(prefix) :].decode("ascii")
    except Exception:
        return None
    out: dict[str, str] = {}
    for token in text.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key] = value
    return out


def encode_transport_hello(client_pub: bytes, cipher: str, cc_mode: str, cleartext_mode: str) -> bytes:
    return encode_ascii_record(
        HELLO_PREFIX,
        pub=b64u(client_pub),
        cipher=cipher,
        cc=cc_mode,
        ct=cleartext_mode,
    )


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


def connect_transport(args, selected_cipher: str, client_private, client_pub: bytes, tofu_label: str, force_family: int | None):
    candidates = resolve_peer_candidates(args.peer_ip, args.peer_port, force_family)
    if not candidates:
        raise SystemExit("no UPing peer candidates")
    last_error = None
    for family, sockaddr in candidates:
        print(f"[UPING] trying {family_name(family)} {sockaddr[0]}:{sockaddr[1]}")
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
                    fields = parse_ascii_record(pkt.payload, CHALLENGE_PREFIX)
                    if not fields:
                        continue
                    token = fields.get("token", "")
                    session_id = fields.get("session", "")
                    session_cipher = normalize_cipher_name(fields.get("cipher", selected_cipher))
                    negotiated_cc = fields.get("cc") or "off"
                    negotiated_cleartext = fields.get("ct") or "off"
                    try:
                        server_pub = b64u_decode(fields["pub"])
                    except Exception:
                        continue
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    check_tofu(args.tofu_file, tofu_label, server_pub)
                    reply = encode_ascii_record(
                        RESPONSE_PREFIX,
                        token=token,
                        session=session_id,
                        cipher=session_cipher,
                        cc=negotiated_cc,
                        ct=negotiated_cleartext,
                        pub=b64u(client_pub),
                    )
                    usock_candidate.send_plain(mkp(TYPE_HELLO, payload=reply).to_bytes(), addr)
                    challenge_reply_sent = True
                    continue
                if pkt.payload.startswith(SESSION_PREFIX):
                    fields = parse_ascii_record(pkt.payload, SESSION_PREFIX)
                    if not fields:
                        continue
                    session_cipher = normalize_cipher_name(fields.get("cipher", selected_cipher))
                    negotiated_cc = fields.get("cc") or "off"
                    negotiated_cleartext = fields.get("ct") or "off"
                    try:
                        server_pub = b64u_decode(fields["pub"])
                    except Exception:
                        continue
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    if negotiated_cc not in ("on", "off"):
                        raise SystemExit(f"server negotiated invalid congestion-control mode {negotiated_cc}")
                    if negotiated_cleartext not in ("on", "off"):
                        raise SystemExit(f"server negotiated invalid cleartext mode {negotiated_cleartext}")
                    if args.congestion_control != negotiated_cc:
                        raise SystemExit(
                            f"server negotiated unexpected congestion-control mode {negotiated_cc}; expected {args.congestion_control}"
                        )
                    if args.cleartext != negotiated_cleartext:
                        raise SystemExit(f"server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                    check_tofu(args.tofu_file, tofu_label, server_pub)
                    server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                    session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                    usock_candidate.set_peer_psk(addr, session_key, session_cipher, cleartext=(negotiated_cleartext == "on"))
                    sender_candidate = USTPSender(
                        sock=usock_candidate,
                        peer=addr,
                        window=256,
                        rto=0.20,
                        max_burst=256,
                        pump_interval=0.001,
                        congestion_control=(negotiated_cc == "on"),
                    )
                    sender_candidate.start()
                    receiver_candidate = USTPReceiver(sock=usock_candidate, peer=addr)
                    print(
                        f"[UPING] connected via {family_name(family)} local={raw_candidate.getsockname()} "
                        f"peer={addr[0]}:{addr[1]} cipher={session_cipher} cc={negotiated_cc} cleartext={negotiated_cleartext}"
                    )
                    return raw_candidate, usock_candidate, addr, sender_candidate, receiver_candidate
            raise TimeoutError(f"{family_name(family)} handshake timed out")
        except Exception as exc:
            last_error = exc
            print(f"[UPING] {family_name(family)} failed: {exc}")
            if raw_candidate is not None:
                try:
                    raw_candidate.close()
                except Exception:
                    pass
    if last_error is not None:
        raise last_error
    raise SystemExit("UPing connection failed")


def close_transport(raw_sock, usock_obj, current_peer, current_sender) -> None:
    try:
        if current_sender is not None:
            current_sender.queue_payload(encode_frame(TYPE_PING, 0, 0, time.monotonic_ns(), b"bye"))
    except Exception:
        pass
    try:
        if usock_obj is not None and current_peer is not None:
            usock_obj.send_plain(mkp(TYPE_CLOSE, payload=b"BYE").to_bytes(), current_peer)
    except Exception:
        pass
    try:
        if current_sender is not None:
            current_sender.stop()
        if raw_sock is not None:
            raw_sock.close()
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
    ap.add_argument("--congestion-control", choices=["on", "off"], default="off", help="Request USTPS Congestion from the server")
    ap.add_argument("--cleartext", choices=["on", "off"], default="off", help="Request cleartext + HMAC instead of AEAD")
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

    raw_sock, usock_obj, current_peer, current_sender, current_receiver = connect_transport(
        args,
        selected_cipher,
        client_private,
        client_pub,
        tofu_label,
        force_family,
    )

    sent = 0
    received = 0
    rtts = []
    seq = 0
    payload = b"Q" * max(0, args.size)
    remote_family = "IPv6" if ":" in current_peer[0] else "IPv4"

    print(f"UPING {args.peer_ip} ({current_peer[0]}) over USTPS: {len(payload)} data bytes, port {args.peer_port}, {remote_family}")

    try:
        while args.count == 0 or sent < args.count:
            seq += 1
            sent_ns = time.monotonic_ns()
            frame = encode_frame(TYPE_PING, 1, seq, sent_ns, payload)
            current_sender.queue_payload(frame)
            sent += 1
            deadline = time.time() + args.timeout
            got_reply = False
            while time.time() < deadline:
                try:
                    raw, _addr = usock_obj.recvfrom(65535)
                except socket.timeout:
                    continue
                pkt = parse_packet(raw)
                if pkt is None:
                    continue
                if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST):
                    current_sender.on_control(pkt)
                    continue
                if pkt.pkt_type == TYPE_CLOSE:
                    raise SystemExit("server closed the UPing session")
                if pkt.pkt_type != TYPE_DATA:
                    continue
                app_payload = current_receiver.handle_data(pkt)
                current_receiver.maybe_nack()
                if not app_payload:
                    continue
                reply = decode_frame(app_payload)
                if reply is None or reply["type"] != TYPE_PONG or reply["seq"] != seq:
                    continue
                rtt_ms = (time.monotonic_ns() - reply["sent_ns"]) / 1_000_000.0
                received += 1
                rtts.append(rtt_ms)
                print(
                    f"{len(reply['payload'])} bytes from {current_peer[0]}:{current_peer[1]}: "
                    f"up_seq={seq} time={rtt_ms:.2f} ms family={remote_family}"
                )
                got_reply = True
                break
            if not got_reply:
                print(f"Request timeout for up_seq={seq}")
            if args.count == 0 or sent < args.count:
                time.sleep(max(0.0, args.interval))
    except KeyboardInterrupt:
        pass
    finally:
        close_transport(raw_sock, usock_obj, current_peer, current_sender)

    loss = ((sent - received) / sent * 100.0) if sent else 0.0
    print(f"\n--- {args.peer_ip} UPing statistics ---")
    print(f"{sent} packets transmitted, {received} received, {loss:.1f}% packet loss")
    if rtts:
        print(f"rtt min/avg/max = {min(rtts):.2f}/{(sum(rtts)/len(rtts)):.2f}/{max(rtts):.2f} ms")


if __name__ == "__main__":
    main()
