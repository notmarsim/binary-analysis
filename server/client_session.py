# server/client_session.py
import os
import socket
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from server.protocol import read_line, send_line, recv_exactly
from models.scan import Scan
from analysis.elf_parser import ElfParser

UPLOAD_DIR = Path("uploads")
MAX_FILE_SIZE = 20 * 1024 * 1024

class ClientSession:
    scans = {}
    next_scan_id = 1

    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.connected = False

    def handle(self):
        print(f"[+] cliente conectado: {self.addr}")
        try:
            while True:
                line = read_line(self.conn)
                if line is None:
                    break
                if not line:
                    continue

                parts = line.split()
                command = parts[0].upper()

                if command == "/CONNECT":
                    self.connected = True
                    send_line(self.conn, "OK CONNECTED")
                elif command == "/UPLOAD":
                    self.handle_upload(parts)
                elif command == "/LIST":
                    self.handle_list()
                elif command == "/INFO":
                    self.handle_info(parts)
                elif command == "/QUIT":
                    send_line(self.conn, "OK BYE")
                    break
                else:
                    send_line(self.conn, "ERR INVALID_COMMAND")
        except Exception as e:
            print(f"[!] Erro na sessao: {e}")
        finally:
            self.conn.close()

    def handle_upload(self, parts: list[str]):
        if not self.connected:
            send_line(self.conn, "ERR NOT_CONNECTED")
            return
        if len(parts) != 3:
            send_line(self.conn, "ERR INVALID_UPLOAD")
            return

        filename = os.path.basename(parts[1])
        try:
            file_size = int(parts[2])
        except ValueError:
            send_line(self.conn, "ERR INVALID_SIZE")
            return

        # Lê os bytes diretamente do buffer sem mandar comandos intermediários
        file_bytes = recv_exactly(self.conn, file_size)
        if file_bytes is None or len(file_bytes) == 0:
            send_line(self.conn, "ERR INCOMPLETE_UPLOAD")
            return

        scan_id = ClientSession.next_scan_id
        ClientSession.next_scan_id += 1

        UPLOAD_DIR.mkdir(exist_ok=True)
        output_path = UPLOAD_DIR / f"{scan_id}_{filename}"
        output_path.write_bytes(file_bytes)

        scan_obj = Scan(scan_id, filename, str(output_path))
        scan_obj.file_size = file_size
        
        parser = ElfParser(output_path)
        scan_obj.header = parser.parse_header_with_binutils()
        scan_obj.hashes = parser.calculate_hashes()

        ClientSession.scans[scan_id] = scan_obj
        send_line(self.conn, f"OK UPLOADED scan_id={scan_id} filename={filename}")

    def handle_list(self):
        if not ClientSession.scans:
            send_line(self.conn, "SCAN ID | FILE\n(Nenhum arquivo analisado)")
            return
        res = "SCAN ID | FILE\n" + "\n".join([f"{sid} | {s.filename}" for sid, s in ClientSession.scans.items()])
        send_line(self.conn, res)

    def handle_info(self, parts: list[str]):
        if len(parts) != 2:
            send_line(self.conn, "ERR MISSING_SCAN_ID")
            return
        try:
            sid = int(parts[1])
        except ValueError:
            send_line(self.conn, "ERR INVALID_SCAN_ID")
            return

        scan = ClientSession.scans.get(sid)
        if not scan:
            send_line(self.conn, "ERR SCAN_NOT_FOUND")
            return

        h = scan.header
        res = (f"File: {scan.filename}\n"
               f"Size: {scan.file_size}\n"
               f"Architecture: {h.get('Machine')}\n"
               f"Type: {h.get('Type')}\n"
               f"Entry Point: {h.get('Entry')}\n"
               f"Sections: {h.get('shnum')}\n"
               f"Program Headers: {h.get('phnum')}")
        send_line(self.conn, res)