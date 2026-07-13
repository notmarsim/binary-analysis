# server/protocol.py
import socket

def read_line(conn: socket.socket) -> str | None:
    data = bytearray()
    while True:
        chunk = conn.recv(1)
        if not chunk:
            return None
        if chunk == b"\n":
            break
        data.extend(chunk)
    return data.decode("utf-8", errors="replace").strip()

def send_line(conn: socket.socket, message: str):
    conn.sendall((message + "\n").encode("utf-8"))

def recv_exactly(conn: socket.socket, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        remaining = size - len(data)
        chunk = conn.recv(min(4096, remaining))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)