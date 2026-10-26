"""VPS-side test peer for quic_relay_probe; never part of the desktop runtime."""
import hashlib
import json
import os
import socket
import struct
import sys


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    value = value.encode()
    return varint(number * 8 + 2) + varint(len(value)) + value


def receive(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(min(65536, size - len(result)))
        if not data:
            raise EOFError("Relay closed")
        result.extend(data)
    return bytes(result)


target, session, public_key = sys.argv[1:]
host, port = target.rsplit(":", 1)
with socket.create_connection((host.strip("[]"), int(port)), timeout=10) as sock:
    sock.settimeout(20)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    request = field(1, "native-quic-peer") + field(2, session) + field(6, public_key)
    request = varint(18 * 8 + 2) + varint(len(request)) + request
    header_size = 1 if len(request) <= 63 else 2
    sock.sendall(((len(request) << 2) | (header_size - 1)).to_bytes(header_size, "little") + request)
    print(json.dumps({"event": "peer_ready", "session": session}), flush=True)
    while True:
        command = receive(sock, 1)
        if command == b"Q":
            break
        size = struct.unpack("!I", receive(sock, 4))[0]
        if not 0 < size <= 8 * 1024 * 1024:
            raise ValueError("Invalid diagnostic payload length")
        if command == b"P":
            sock.sendall(receive(sock, size))
        elif command == b"D":
            payload = os.urandom(size)
            sock.sendall(payload + hashlib.sha256(payload).digest())
        elif command == b"U":
            sock.sendall(hashlib.sha256(receive(sock, size)).digest())
        else:
            raise ValueError("Invalid diagnostic command")
