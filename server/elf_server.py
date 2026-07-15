import socket
import threading
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from server.client_session import ClientSession

HOST = "0.0.0.0"
PORT = 9000

class ElfAnalysisServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"[+] servidor escutando em {self.host}:{self.port}")

            while True:
                conn, addr = server_socket.accept()
                session = ClientSession(conn, addr)
                thread = threading.Thread(target=session.handle)
                thread.daemon = True
                thread.start()

if __name__ == "__main__":
    server = ElfAnalysisServer(HOST, PORT)
    server.start()