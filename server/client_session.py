import socket
import sys
import threading
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from wire_protocol import (
    ProtocolError,
    decode_upload_filename,
    read_command,
    recv_exactly,
    send_response,
)
from models.scan import Scan
from analysis.elf_parser import ElfParser, has_elf_magic
from protocol_limits import (
    MAX_FILE_SIZE_BYTES,
    MAX_FILENAME_SIZE_BYTES,
    SERVER_SESSION_TIMEOUT_SECONDS,
)
from analysis import hashing, similarity, report_html

UPLOAD_DIR = Path("uploads")

class ClientSession:
    scans: dict[int, Scan] = {}
    next_scan_id = 1
    _state_lock = threading.RLock()

    @classmethod
    def _reserve_scan_id(cls) -> int:
        with cls._state_lock:
            scan_id = cls.next_scan_id
            cls.next_scan_id += 1
            return scan_id

    @classmethod
    def _store_scan(cls, scan: Scan) -> None:
        with cls._state_lock:
            cls.scans[scan.scan_id] = scan

    @classmethod
    def _get_scan(cls, scan_id: int) -> Scan | None:
        with cls._state_lock:
            return cls.scans.get(scan_id)

    @classmethod
    def _get_scans(cls, *scan_ids: int) -> tuple[Scan | None, ...]:
        with cls._state_lock:
            return tuple(cls.scans.get(scan_id) for scan_id in scan_ids)

    @classmethod
    def _snapshot_scans(cls) -> list[tuple[int, Scan]]:
        with cls._state_lock:
            return sorted(cls.scans.items())

    def __init__(
        self,
        conn: socket.socket,
        addr,
        *,
        timeout_seconds: float = SERVER_SESSION_TIMEOUT_SECONDS,
    ):
        self.conn = conn
        self.conn.settimeout(timeout_seconds)
        self.addr = addr
        self.connected = False

    def handle(self):
        print(f"[+] cliente conectado: {self.addr}")
        try:
            while True:
                line = read_command(self.conn)
                if line is None: break
                if not line: continue

                parts = line.split()
                command = parts[0].upper()

                if command == "/CONNECT":
                    self.connected = True
                    send_response(self.conn, "OK CONNECTED")
                elif command == "/UPLOAD":
                    if not self.handle_upload(parts):
                        break
                elif command == "/LIST":
                    self.handle_list()
                elif command == "/COMPARE":
                    self.handle_compare(parts)
                elif command == "/QUIT":
                    send_response(self.conn, "OK BYE")
                    break
                elif command == "/HEX":
                    self.handle_hex(parts)
                elif command == "/SDUMP":
                    self.handle_sdump(parts)
                elif command == "/DIS":
                    self.handle_dis(parts)
                
                elif command in [
                    "/INFO",
                    "/HASHES",
                    "/SECTION_HEADERS",
                    "/PROGRAM_HEADERS",
                    "/STRINGS",
                    "/SYMBOLS",
                    "/REPORT"
                ]:
                    self.handle_analysis_commands(command, parts)
                elif command == "/HELP":
                    self.handle_help()
                else:
                    send_response(self.conn, "ERR INVALID_COMMAND")
        except socket.timeout:
            print(f"[!] tempo limite excedido para {self.addr}")
            try:
                send_response(self.conn, "ERR TIMEOUT")
            except OSError:
                pass
        except ProtocolError as exc:
            print(f"[!] erro de protocolo com {self.addr}: {exc}")
        except Exception as e:
            print(f"[!] Erro na sessao: {e}")
        finally:
            self.conn.close()

    def handle_upload(self, parts: list[str]) -> bool:
        if not self.connected:
            send_response(self.conn, "ERR NOT_CONNECTED")
            return True
        if len(parts) != 3:
            send_response(self.conn, "ERR INVALID_UPLOAD")
            return True

        try:
            filename_size = int(parts[1])
            file_size = int(parts[2])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SIZE")
            return True

        if not 1 <= filename_size <= MAX_FILENAME_SIZE_BYTES:
            send_response(
                self.conn,
                f"ERR INVALID_FILENAME_SIZE max_bytes={MAX_FILENAME_SIZE_BYTES}",
            )
            return True

        if file_size <= 0:
            send_response(self.conn, "ERR INVALID_SIZE")
            return True

        if file_size > MAX_FILE_SIZE_BYTES:
            send_response(
                self.conn,
                f"ERR FILE_TOO_LARGE max_bytes={MAX_FILE_SIZE_BYTES}",
            )
            return True

        send_response(self.conn, "OK READY")

        try:
            filename_bytes = recv_exactly(self.conn, filename_size)
        except ProtocolError:
            send_response(self.conn, "ERR INCOMPLETE_FILENAME")
            return False

        try:
            filename = decode_upload_filename(filename_bytes)
        except ProtocolError:
            send_response(self.conn, "ERR INVALID_FILENAME")
            return False

        try:
            file_bytes = recv_exactly(self.conn, file_size)
        except ProtocolError:
            send_response(self.conn, "ERR INCOMPLETE_UPLOAD")
            return False

        if not has_elf_magic(file_bytes):
            send_response(
                self.conn,
                "ERR UNSUPPORTED_FORMAT expected=ELF",
            )
            return True

        scan_id = ClientSession._reserve_scan_id()

        UPLOAD_DIR.mkdir(exist_ok=True)
        output_path = UPLOAD_DIR / f"{scan_id}_{filename}"
        output_path.write_bytes(file_bytes)

        scan_obj = Scan(scan_id, filename, str(output_path))
        scan_obj.file_size = file_size

        parser = ElfParser(output_path)
        scan_obj.header = parser.parse_header_with_binutils()
        scan_obj.hashes = parser.calculate_hashes()

        ClientSession._store_scan(scan_obj)
        send_response(
            self.conn,
            f"OK UPLOADED scan_id={scan_id} filename={filename}",
        )
        return True

    def handle_list(self):
        scans = ClientSession._snapshot_scans()
        if not scans:
            send_response(self.conn, "SCAN ID | FILE\n(Nenhum arquivo analisado)")
            return

        rows = "\n".join(
            f"{scan_id} | {scan.filename}" for scan_id, scan in scans
        )
        send_response(self.conn, f"SCAN ID | FILE\n{rows}")

    def handle_help(self):
        help_text = (
            "=== COMANDOS DISPONÍVEIS ===\n"
            "/CONNECT              - Estabelece a conexão inicial com o servidor.\n"
            "/UPLOAD <caminho>     - Envia um binário ELF local para análise.\n"
            "/LIST                 - Lista todos os arquivos já enviados e seus respectivos SCAN IDs.\n"
            "/COMPARE <id1> <id2>  - Compara dois binários via SSDEEP e retorna a similaridade (0 a 100%).\n"
            "/INFO <id>            - Exibe um resumo técnico do cabeçalho (Arquitetura, Entry Point, etc).\n"
            "/HASHES <id>          - Exibe MD5, SHA-1, SHA-256 e SSDEEP do arquivo.\n"
            "/SECTION_HEADERS <id> - Lista as Section Headers (tabela de seções) do binário.\n"
            "/PROGRAM_HEADERS <id> - Exibe os cabeçalhos de programa (segmentos de execução).\n"
            "/STRINGS <id>         - Extrai e exibe as strings imprimíveis contidas no binário.\n"
            "/SYMBOLS <id>         - Exibe a tabela de símbolos (funções e variáveis globais).\n"
            "/HEX <id> [off] [len] - Exibe o dump hexadecimal a partir de um offset e tamanho opcionais.\n"
            "/SDUMP <id> <secao>   - Exibe o dump de dados de uma seção específica (ex.: .rodata) via objdump.\n"
            "/DIS <id>             - Desmonta o código de máquina do ELF em Assembly (Disassembly).\n"
            "/REPORT <id>          - Gera um report HTML com informações úteis sobre o binário. \n"
            "/HELP                 - Mostra este menu de ajuda com comandos e funcionalidades.\n"
            "/QUIT                 - Encerra a sessão com o servidor com segurança.\n"
        )
        send_response(self.conn, help_text.rstrip("\n"))

    def handle_compare(self, parts: list[str]):
        if len(parts) != 3:
            send_response(self.conn, "ERR MISSING_ARGS. Uso: /COMPARE <id1> <id2>")
            return
            
        try:
            id1 = int(parts[1])
            id2 = int(parts[2])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SCAN_ID")
            return
            
        scan1, scan2 = ClientSession._get_scans(id1, id2)
        
        if not scan1 or not scan2:
            send_response(self.conn, "ERR SCAN_NOT_FOUND (Verifique os IDs com /LIST)")
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
        send_response(self.conn, res.rstrip("\n"))

    def handle_analysis_commands(self, command: str, parts: list[str]):
        """Centraliza e valida comandos que exigem a passagem do ID do binário analisado"""
        if len(parts) != 2:
            send_response(self.conn, f"ERR MISSING_SCAN_ID. Uso: {command} <id>")
            return
        try:
            sid = int(parts[1])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SCAN_ID")
            return

        scan = ClientSession._get_scan(sid)
        if not scan:
            send_response(self.conn, "ERR SCAN_NOT_FOUND")
            return

        if command == "/HASHES":
            labels = (
                ("MD5", "MD5"),
                ("SHA1", "SHA-1"),
                ("SHA256", "SHA-256"),
                ("SSDEEP", "SSDEEP"),
            )
            lines = [f"OK HASHES FOR SCAN {sid}"]
            lines.extend(
                f"{label}: {scan.hashes.get(key, 'N/A')}"
                for key, label in labels
            )
            send_response(self.conn, "\n".join(lines))
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
                                  
            send_response(self.conn, res.rstrip("\n"))

        elif command == "/SECTION_HEADERS":
            res = parser.get_section_headers()
            send_response(self.conn, f"OK SECTIONS FOR SCAN {sid}\n{res}")

        elif command == "/PROGRAM_HEADERS":
            res = parser.get_program_headers()
            send_response(self.conn, f"OK PROGRAM HEADERS FOR SCAN {sid}\n{res}")

        elif command == "/STRINGS":
            res = parser.get_strings() 
            send_response(self.conn, f"OK STRINGS FOR SCAN {sid}\n{res}")

        elif command == "/SYMBOLS":
            res = parser.get_symbols()
            send_response(self.conn, f"OK SYMBOLS FOR SCAN {sid}\n{res}")

        elif command == "/REPORT":
            html_content = report_html.generate_html(
                parser, 
                scan.filename, 
                scan.file_size, 
                scan.hashes, 
                scan.header
            )
            send_response(self.conn, f"OK REPORT_GENERATED\n{html_content}")

    def handle_hex(self, parts: list[str]):
        """Manipula o comando /HEX <id> [offset] [length] com parâmetros opcionais."""
        if len(parts) < 2 or len(parts) > 4:
            send_response(self.conn, "ERR MISSING_ARGS. Uso: /HEX <id> [offset] [length]")
            return

        try:
            sid = int(parts[1])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SCAN_ID")
            return

        offset = 0
        length = 32

        if len(parts) >= 3:
            try:
                offset = int(parts[2])
                if offset < 0: raise ValueError
            except ValueError:
                send_response(self.conn, "ERR INVALID_OFFSET. Deve ser um inteiro positivo.")
                return

        if len(parts) == 4:
            try:
                length = int(parts[3])
                if length <= 0 or length > 1024: raise ValueError
            except ValueError:
                send_response(self.conn, "ERR INVALID_LENGTH. Use um valor entre 1 e 1024.")
                return

        scan = ClientSession._get_scan(sid)
        if not scan:
            send_response(self.conn, "ERR SCAN_NOT_FOUND")
            return

        parser = ElfParser(Path(scan.filepath))
        res = parser.get_hex_dump(offset, length)
        send_response(self.conn, f"OK HEX DUMP FOR SCAN {sid} (Offset: {offset}, Length: {length})\n{res}")

    def handle_sdump(self, parts: list[str]):
        """Manipula o comando /SDUMP <id> <nome_da_secao>."""
        if len(parts) != 3:
            send_response(self.conn, "ERR MISSING_ARGS. Uso: /SDUMP <id> <secao>")
            return

        try:
            sid = int(parts[1])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SCAN_ID")
            return

        section_name = parts[2]
        scan = ClientSession._get_scan(sid)
        if not scan:
            send_response(self.conn, "ERR SCAN_NOT_FOUND")
            return

        parser = ElfParser(Path(scan.filepath))
        res = parser.get_section_dump(section_name)
        send_response(self.conn, f"OK SECTION DUMP FOR '{section_name}' (SCAN {sid})\n{res}")

    def handle_dis(self, parts: list[str]):
        """Manipula o comando /DIS <id> para desmontar as instruções executáveis."""
        if len(parts) != 2:
            send_response(self.conn, "ERR MISSING_ARGS. Uso: /DIS <id>")
            return

        try:
            sid = int(parts[1])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SCAN_ID")
            return

        scan = ClientSession._get_scan(sid)
        if not scan:
            send_response(self.conn, "ERR SCAN_NOT_FOUND")
            return

        parser = ElfParser(Path(scan.filepath))
        res = parser.get_disassembly()
        send_response(self.conn, f"OK ASSEMBLY DISASSEMBLY FOR SCAN {sid}\n{res}")

    def handle_report(self, parts: list[str]):
        """Manipula o comando /REPORT <id> gerando uma estrutura HTML consolidada."""
        if len(parts) != 2:
            send_response(self.conn, "ERR MISSING_SCAN_ID. Uso: /REPORT <id>")
            return
        try:
            sid = int(parts[1])
        except ValueError:
            send_response(self.conn, "ERR INVALID_SCAN_ID")
            return

        scan = ClientSession._get_scan(sid)
        if not scan:
            send_response(self.conn, "ERR SCAN_NOT_FOUND")
            return

        parser = ElfParser(Path(scan.filepath))
        
        html_content = parser.get_html_report(scan.filename, scan.file_size, scan.hashes, scan.header)
        
        send_response(self.conn, f"OK REPORT_GENERATED\n{html_content}")
