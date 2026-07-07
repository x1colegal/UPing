import struct


MAGIC = b"UPNG"
HEADER_FMT = "!4sBBIIQH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

TYPE_PING = 1
TYPE_PONG = 2


def encode_frame(frame_type: int, ping_id: int, seq: int, sent_ns: int, payload: bytes = b"") -> bytes:
    return struct.pack(
        HEADER_FMT,
        MAGIC,
        1,
        frame_type,
        ping_id & 0xFFFFFFFF,
        seq & 0xFFFFFFFF,
        sent_ns & 0xFFFFFFFFFFFFFFFF,
        len(payload),
    ) + payload


def decode_frame(raw: bytes) -> dict | None:
    if len(raw) < HEADER_SIZE:
        return None
    magic, version, frame_type, ping_id, seq, sent_ns, length = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
    if magic != MAGIC or version != 1:
        return None
    payload = raw[HEADER_SIZE:HEADER_SIZE + length]
    if len(payload) != length:
        return None
    return {
        "type": frame_type,
        "ping_id": ping_id,
        "seq": seq,
        "sent_ns": sent_ns,
        "payload": payload,
    }
