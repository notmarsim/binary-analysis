# elf_client.py
import socket
import sys
from pathlib import Path

HOST = "127.0.0.1"
PORT = 9000

def read_response(sock: socket.socket) -> str:
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk or chunk == b"\n":
            break
        data.extend(chunk)
    return data.decode("utf-8", errors="replace").strip()

def send_line(sock: socket.socket, line: str):
    sock.sendall((line + "\n").encode("utf-8"))

def upload_file(sock: socket.socket, file_path: Path):
    file_bytes = file_path.read_bytes()
    filename = file_path.name
    size = len(file_bytes)

    send_line(sock, f"/UPLOAD {filename} {size}")
    sock.sendall(file_bytes)

    response = read_response(sock)
    print("servidor:", response)

def main():
    if len(sys.argv) != 2:
        print("uso: python elf_client.py caminho_do_arquivo_elf")
        return

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print("arquivo nao encontrado")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        send_line(sock, "/CONNECT")
        print("servidor:", read_response(sock))

        upload_file(sock, file_path)

        send_line(sock, "/QUIT")
        print("servidor:", read_response(sock))

if __name__ == "__main__":
    main()