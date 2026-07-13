import os
import socket
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from server.protocol import read_line, send_line, recv_exactly
from models.scan import Scan
from analysis.elf_parser import ElfParser
from protocol_limits import MAX_FILE_SIZE_BYTES
from analysis import hashing, similarity

UPLOAD_DIR = Path("uploads")

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
                if line is None: break
                if not line: continue

                parts = line.split()
                command = parts[0].upper()

                if command == "/CONNECT":
                    self.connected = True
                    send_line(self.conn, "OK CONNECTED\n")
                elif command == "/UPLOAD":
                    if not self.handle_upload(parts):
                        break
                elif command == "/LIST":
                    self.handle_list()
                elif command == "/COMPARE":
                    self.handle_compare(parts)
                elif command == "/QUIT":
                    send_line(self.conn, "OK BYE\n")
                    break
                
                elif command in ["/INFO", "/SECTION_HEADERS", "/PROGRAM_HEADERS", "/STRINGS", "/SYMBOLS"]:
                    self.handle_analysis_commands(command, parts)
                elif command == "/HELP":
                    self.handle_help()
                else:
                    send_line(self.conn, "ERR INVALID_COMMAND\n")
        except Exception as e:
            print(f"[!] Erro na sessao: {e}")
        finally:
            self.conn.close()

    def handle_upload(self, parts: list[str]) -> bool:
        if not self.connected:
            send_line(self.conn, "ERR NOT_CONNECTED\n")
            return True
        if len(parts) != 3:
            send_line(self.conn, "ERR INVALID_UPLOAD\n")
            return True

        filename = os.path.basename(parts[1])
        try:
            file_size = int(parts[2])
        except ValueError:
            send_line(self.conn, "ERR INVALID_SIZE\n")
            return False

        if file_size <= 0:
            send_line(self.conn, "ERR INVALID_SIZE\n")
            return False

        if file_size > MAX_FILE_SIZE_BYTES:
            send_line(
                self.conn,
                f"ERR FILE_TOO_LARGE max_bytes={MAX_FILE_SIZE_BYTES}\n",
            )
            return False

        file_bytes = recv_exactly(self.conn, file_size)
        if file_bytes is None or len(file_bytes) == 0:
            send_line(self.conn, "ERR INCOMPLETE_UPLOAD\n")
            return False

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
        send_line(self.conn, f"OK UPLOADED scan_id={scan_id} filename={filename}\n")
        return True

    def handle_list(self):
        if not ClientSession.scans:
            send_line(self.conn, "SCAN ID | FILE\n(Nenhum arquivo analisado)\n")
            return
        res = "SCAN ID | FILE\n" + "\n".join([f"{sid} | {s.filename}" for sid, s in ClientSession.scans.items()])
        send_line(self.conn, res + "\n")

    def handle_help(self):
        """Etapa 20: Retorna a lista de comandos disponíveis e suas respectivas funções"""
        help_text = (
            "=== COMANDOS DISPONÍVEIS ===\n"
            "/CONNECT              - Estabelece a conexão inicial com o servidor.\n"
            "/UPLOAD <caminho>     - Envia um binário ELF local para análise.\n"
            "/LIST                 - Lista todos os arquivos já enviados e seus respectivos SCAN IDs.\n"
            "/COMPARE <id1> <id2>  - Compara dois binários via SSDEEP e retorna a similaridade (0 a 100%).\n"
            "/INFO <id>            - Exibe um resumo técnico do cabeçalho (Arquitetura, Entry Point, etc).\n"
            "/SECTION_HEADERS <id> - Lista as Section Headers (tabela de seções) do binário.\n"
            "/PROGRAM_HEADERS <id> - Exibe os cabeçalhos de programa (segmentos de execução).\n"
            "/STRINGS <id>         - Extrai e exibe as strings imprimíveis contidas no binário.\n"
            "/SYMBOLS <id>         - Exibe a tabela de símbolos (funções e variáveis globais).\n"
            "/HELP                 - Mostra este menu de ajuda com comandos e funcionalidades.\n"
            "/QUIT                 - Encerra a sessão com o servidor com segurança.\n"
        )
       
        send_line(self.conn, help_text + "\n")

    def handle_compare(self, parts: list[str]):
        if len(parts) != 3:
            send_line(self.conn, "ERR MISSING_ARGS. Uso: /COMPARE <id1> <id2>\n")
            return
            
        try:
            id1 = int(parts[1])
            id2 = int(parts[2])
        except ValueError:
            send_line(self.conn, "ERR INVALID_SCAN_ID\n")
            return
            
        scan1 = ClientSession.scans.get(id1)
        scan2 = ClientSession.scans.get(id2)
        
        if not scan1 or not scan2:
            send_line(self.conn, "ERR SCAN_NOT_FOUND (Verifique os IDs com /LIST)\n")
            return
            
        hash1 = scan1.hashes.get("SSDEEP", "")
        hash2 = scan2.hashes.get("SSDEEP", "")
        
        parser1 = ElfParser(Path(scan1.filepath))
        parser2 = ElfParser(Path(scan2.filepath))

        ssdeep_score = hashing.calculate_similarity(
        hash1,
        hash2
        )

        string_score = similarity.compare_strings(
            parser1,
            parser2
        )

        section_score = similarity.compare_sections(
            parser1,
            parser2
        )

        symbol_score = similarity.compare_symbols(
            parser1,
            parser2
        )

        res = (
            "=== COMPARAÇÃO DE BINÁRIOS ELF ===\n"

            f"[ID {id1}] Arquivo: {scan1.filename}\n"
            f"[ID {id2}] Arquivo: {scan2.filename}\n"

            "---- Similaridade ----\n"

            f"SSDEEP: {ssdeep_score}%\n"
            f"Sections: {section_score}%\n"
            f"Symbols: {symbol_score}%\n"
            f"Strings: {string_score}%\n"
        )
        send_line(self.conn, res + "\n")

    def handle_analysis_commands(self, command: str, parts: list[str]):
        """Centraliza e valida comandos que exigem a passagem do ID do binário analisado"""
        if len(parts) != 2:
            send_line(self.conn, f"ERR MISSING_SCAN_ID. Uso: {command} <id>\n")
            return
        try:
            sid = int(parts[1])
        except ValueError:
            send_line(self.conn, "ERR INVALID_SCAN_ID\n")
            return

        scan = ClientSession.scans.get(sid)
        if not scan:
            send_line(self.conn, "ERR SCAN_NOT_FOUND\n")
            return

        parser = ElfParser(Path(scan.filepath))

        if command == "/INFO":
            h = scan.header
            res = (f"File: {scan.filename}\n"
                   f"Size: {scan.file_size}\n"
                   f"Architecture: {h.get('Machine')}\n"
                   f"Type: {h.get('Type')}\n"
                   f"Entry Point: {h.get('Entry')}\n"
                   f"Sections: {h.get('shnum')}\n"
                   f"Program Headers: {h.get('phnum')}\n"
                   f"SSDEEP: {scan.hashes.get('SSDEEP', 'N/A')}")
                                  
            send_line(self.conn, res + "\n")

        elif command == "/SECTION_HEADERS":
            res = parser.get_section_headers()
            send_line(self.conn, f"OK SECTIONS FOR SCAN {sid}\n" + res + "\n")

        elif command == "/PROGRAM_HEADERS":
            res = parser.get_program_headers()
            send_line(self.conn, f"OK PROGRAM HEADERS FOR SCAN {sid}\n" + res + "\n")

        elif command == "/STRINGS":
            res = parser.get_strings().split()
            send_line(self.conn, f"OK STRINGS FOR SCAN {sid}\n" + res + "\n")

        elif command == "/SYMBOLS":
            res = parser.get_symbols()
            send_line(self.conn, f"OK SYMBOLS FOR SCAN {sid}\n" + res + "\n")