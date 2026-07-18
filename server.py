import argparse
import base64
import errno
import os
import secrets
import socket
import threading
import time
import shlex
from dataclasses import dataclass

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
SYSTEMD_UNIT_PATH = "/etc/systemd/system/uping-server.service"


@dataclass
class PendingChallenge:
    addr: tuple[str, int]
    client_pub: bytes
    cipher: str
    congestion_control: str
    cleartext: str
    session_id: str
    token: str
    created_ts: float


@dataclass
class ClientSession:
    addr: tuple[str, int]
    sender: USTPSender
    receiver: USTPReceiver
    cipher: str
    session_psk: bytes
    client_pub: bytes
    server_pub: bytes
    session_id: str
    session_reply: bytes
    cleartext: bool
    last_seen_ts: float = time.time()


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


def parse_client_hello(payload: bytes):
    fields = parse_ascii_record(payload, HELLO_PREFIX)
    if fields is not None:
        try:
            client_pub = b64u_decode(fields["pub"])
        except Exception:
            return None
        cipher = normalize_cipher_name(fields.get("cipher", "chacha20"))
        cc_mode = fields.get("cc")
        cleartext = fields.get("ct")
        return ("init", client_pub, cipher, cc_mode, cleartext)
    fields = parse_ascii_record(payload, RESPONSE_PREFIX)
    if fields is not None:
        try:
            token = fields["token"]
            session_id = fields["session"]
            client_pub = b64u_decode(fields["pub"])
            cipher = normalize_cipher_name(fields["cipher"])
        except Exception:
            return None
        cc_mode = fields.get("cc")
        cleartext = fields.get("ct")
        return ("challenge_reply", token, session_id, client_pub, cipher, cc_mode, cleartext)
    return None


def resolve_server_cc_mode(server_mode: str, client_mode: str | None) -> str:
    if server_mode == "on":
        return "on"
    if server_mode == "off":
        return "off"
    return "on" if client_mode == "on" else "off"


def resolve_server_cleartext_mode(server_mode: str, client_mode: str | None) -> str:
    if server_mode == "on":
        return "on"
    if server_mode == "off":
        return "off"
    return "on" if client_mode == "on" else "off"


def load_or_create_host_key(path: str) -> x25519.X25519PrivateKey:
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) == 32:
            return x25519.X25519PrivateKey.from_private_bytes(raw)
    except FileNotFoundError:
        pass
    key = x25519.X25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def create_server_udp_socket(bind_ip: str, bind_port: int) -> socket.socket:
    bind_host = "::" if bind_ip == "0.0.0.0" else bind_ip
    infos = socket.getaddrinfo(bind_host, bind_port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    last_error = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            if family == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            tune_udp_socket(sock)
            sock.bind(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            try:
                sock.close()
            except Exception:
                pass
    if last_error is not None:
        raise last_error
    raise OSError(errno.EADDRNOTAVAIL, "unable to bind UDP socket")


def systemd_available() -> bool:
    return os.path.isdir("/run/systemd/system") and os.path.isdir("/etc/systemd/system")


def build_systemd_unit(args: argparse.Namespace) -> str:
    cmd = [
        "python3",
        os.path.abspath(__file__),
        "--start",
    ]
    if args.bind_ip != "0.0.0.0":
        cmd.extend(["--bind-ip", args.bind_ip])
    if args.bind_port != DEFAULT_PORT:
        cmd.extend(["--bind-port", str(args.bind_port)])
    if args.cipher != "auto":
        cmd.extend(["--cipher", args.cipher])
    if args.congestion_control != "auto":
        cmd.extend(["--congestion-control", args.congestion_control])
    if args.cleartext != "auto":
        cmd.extend(["--cleartext", args.cleartext])
    if args.host_key_file != os.path.expanduser("~/.uping_host_key"):
        cmd.extend(["--host-key-file", args.host_key_file])
    if args.window != 256:
        cmd.extend(["--window", str(args.window)])
    if args.rto != 0.20:
        cmd.extend(["--rto", str(args.rto)])
    exec_start = " ".join(shlex.quote(part) for part in cmd)
    return (
        "[Unit]\n"
        "Description=UPing server (USTPS-Ping)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={shlex.quote(os.path.dirname(os.path.abspath(__file__)))}\n"
        f"ExecStart={exec_start}\n"
        "Restart=always\n"
        "RestartSec=2\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def maybe_install_systemd(args: argparse.Namespace) -> None:
    if not systemd_available() or os.geteuid() != 0:
        return
    unit_text = build_systemd_unit(args)
    current = None
    try:
        with open(SYSTEMD_UNIT_PATH, "r", encoding="utf-8") as f:
            current = f.read()
    except FileNotFoundError:
        pass
    if current != unit_text:
        with open(SYSTEMD_UNIT_PATH, "w", encoding="utf-8") as f:
            f.write(unit_text)
        print(f"[UPING-SERVER] systemd unit updated at {SYSTEMD_UNIT_PATH}")
    os.system("systemctl daemon-reload >/dev/null 2>&1")
    os.system("systemctl enable uping-server.service >/dev/null 2>&1")
    os.system("systemctl restart uping-server.service >/dev/null 2>&1")
    if current is None:
        print(f"[UPING-SERVER] systemd unit installed automatically at {SYSTEMD_UNIT_PATH}")


def maybe_configure_and_exit(args: argparse.Namespace) -> None:
    if args.start:
        return
    maybe_install_systemd(args)
    if systemd_available() and os.geteuid() == 0:
        print("[UPING-SERVER] configuration completed")
        raise SystemExit(0)


def main() -> None:
    ap = argparse.ArgumentParser(description="UPing server: USTPS ping responder")
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--cipher", default="auto", help="auto | chacha20 | aes-256-gcm | aes-128-gcm")
    ap.add_argument("--congestion-control", choices=["auto", "on", "off"], default="auto")
    ap.add_argument("--cleartext", choices=["auto", "on", "off"], default="auto")
    ap.add_argument("--host-key-file", default=os.path.expanduser("~/.uping_host_key"))
    ap.add_argument("--window", type=int, default=256)
    ap.add_argument("--rto", type=float, default=0.20)
    ap.add_argument("--loss", type=int, default=0, help="Simulated outbound packet loss percent (0-100)")
    args = ap.parse_args()

    maybe_configure_and_exit(args)

    raw_sock = create_server_udp_socket(args.bind_ip, args.bind_port)
    selected_cipher = None if args.cipher == "auto" else normalize_cipher_name(args.cipher)
    host_private = load_or_create_host_key(args.host_key_file)
    host_public = public_bytes(host_private.public_key())
    sock = AEADDatagramSocket(raw_sock, cipher_name=selected_cipher or "chacha20")

    sessions: dict[tuple[str, int], ClientSession] = {}
    pending_challenges: dict[tuple[str, int], PendingChallenge] = {}
    sessions_lock = threading.RLock()

    print(f"[UPING-SERVER] listening on {args.bind_ip}:{args.bind_port}")

    def send_challenge(addr: tuple[str, int], client_pub_raw: bytes, requested_cipher: str | None, requested_cc: str | None, requested_cleartext: str | None) -> None:
        cipher = selected_cipher or requested_cipher or "chacha20"
        cc_mode = resolve_server_cc_mode(args.congestion_control, requested_cc)
        cleartext_mode = resolve_server_cleartext_mode(args.cleartext, requested_cleartext)
        challenge = PendingChallenge(
            addr=addr,
            client_pub=client_pub_raw,
            cipher=cipher,
            congestion_control=cc_mode,
            cleartext=cleartext_mode,
            session_id=b64u(secrets.token_bytes(18)),
            token=b64u(secrets.token_bytes(18)),
            created_ts=time.time(),
        )
        pending_challenges[addr] = challenge
        payload = encode_ascii_record(
            CHALLENGE_PREFIX,
            token=challenge.token,
            session=challenge.session_id,
            cipher=challenge.cipher,
            cc=challenge.congestion_control,
            ct=challenge.cleartext,
            pub=b64u(host_public),
        )
        sock.send_plain(mkp(TYPE_HELLO, payload=payload).to_bytes(), addr)

    def finish_session(session: ClientSession) -> None:
        try:
            session.sender.stop()
        except Exception:
            pass
        try:
            sock.clear_peer(session.addr)
        except Exception:
            pass

    def new_session(addr: tuple[str, int], challenge: PendingChallenge) -> ClientSession:
        client_pub = x25519.X25519PublicKey.from_public_bytes(challenge.client_pub)
        session_psk = derive_session_key(host_private.exchange(client_pub), challenge.client_pub, host_public)
        session_reply = encode_ascii_record(
            SESSION_PREFIX,
            session=challenge.session_id,
            cipher=challenge.cipher,
            cc=challenge.congestion_control,
            ct=challenge.cleartext,
            pub=b64u(host_public),
        )
        sock.send_plain(mkp(TYPE_HELLO, payload=session_reply).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, challenge.cipher, cleartext=(challenge.cleartext == "on"))
        sender = USTPSender(
            sock=sock,
            peer=addr,
            window=args.window,
            rto=args.rto,
            loss_percent=args.loss,
            congestion_control=(challenge.congestion_control == "on"),
        )
        sender.start()
        receiver = USTPReceiver(sock=sock, peer=addr)
        session = ClientSession(
            addr=addr,
            sender=sender,
            receiver=receiver,
            cipher=challenge.cipher,
            session_psk=session_psk,
            client_pub=challenge.client_pub,
            server_pub=host_public,
            session_id=challenge.session_id,
            session_reply=session_reply,
            cleartext=(challenge.cleartext == "on"),
            last_seen_ts=time.time(),
        )
        sessions[addr] = session
        print(
            f"[UPING-SERVER] session ready {addr[0]}:{addr[1]} "
            f"cipher={challenge.cipher} cc={challenge.congestion_control} cleartext={challenge.cleartext}"
        )
        return session

    try:
        while True:
            raw, addr = sock.recvfrom(65535)
            pkt = parse_packet(raw)
            if pkt is None:
                continue

            with sessions_lock:
                session = sessions.get(addr)
                if session is not None:
                    session.last_seen_ts = time.time()

            if pkt.pkt_type == TYPE_HELLO:
                parsed = parse_client_hello(pkt.payload)
                if parsed is None:
                    continue
                if parsed[0] == "init":
                    _, client_pub, requested_cipher, requested_cc, requested_cleartext = parsed
                    with sessions_lock:
                        send_challenge(addr, client_pub, requested_cipher, requested_cc, requested_cleartext)
                    continue
                if parsed[0] == "challenge_reply":
                    _, token, session_id, client_pub, requested_cipher, requested_cc, requested_cleartext = parsed
                    with sessions_lock:
                        pending = pending_challenges.get(addr)
                        if (
                            pending is None
                            or pending.token != token
                            or pending.session_id != session_id
                            or pending.client_pub != client_pub
                            or pending.cipher != requested_cipher
                            or pending.congestion_control != (requested_cc or pending.congestion_control)
                            or pending.cleartext != (requested_cleartext or pending.cleartext)
                        ):
                            continue
                        new_session(addr, pending)
                        pending_challenges.pop(addr, None)
                    continue

            with sessions_lock:
                session = sessions.get(addr)
            if session is None:
                continue

            if pkt.pkt_type == TYPE_CLOSE:
                finish_session(session)
                with sessions_lock:
                    sessions.pop(addr, None)
                continue

            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                session.sender.on_control(pkt)
                continue

            if pkt.pkt_type != TYPE_DATA:
                continue

            payload = session.receiver.handle_data(pkt)
            session.receiver.maybe_nack()
            if not payload:
                continue
            frame = decode_frame(payload)
            if frame is None:
                continue
            if frame["type"] == TYPE_PING:
                pong = encode_frame(TYPE_PONG, frame["ping_id"], frame["seq"], frame["sent_ns"], frame["payload"])
                session.sender.queue_payload(pong)
    except KeyboardInterrupt:
        print("[UPING-SERVER] interrupted")
    finally:
        for session in list(sessions.values()):
            finish_session(session)
        raw_sock.close()


if __name__ == "__main__":
    main()
