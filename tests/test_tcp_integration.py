import hashlib
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from server.client_session import ClientSession
from wire_protocol import read_response, send_command


class TcpSessionHarness:
    """Executa uma ClientSession sobre um socket TCP real em porta efêmera."""

    def __init__(self, *, timeout_seconds: float = 1.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.errors: list[BaseException] = []
        self.thread = threading.Thread(target=self._serve_once, daemon=True)

    def _serve_once(self) -> None:
        try:
            conn, addr = self.listener.accept()
            ClientSession(
                conn,
                addr,
                timeout_seconds=self.timeout_seconds,
            ).handle()
        except BaseException as exc:  # propagado no encerramento do harness
            self.errors.append(exc)
        finally:
            self.listener.close()

    def __enter__(self) -> "TcpSessionHarness":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.listener.close()
        self.thread.join(timeout=2)

        if self.thread.is_alive():
            raise AssertionError("a sessão TCP não encerrou dentro do prazo")
        if self.errors:
            raise AssertionError("erro na thread do servidor") from self.errors[0]

    def connect(self) -> socket.socket:
        sock = socket.create_connection(
            ("127.0.0.1", self.port),
            timeout=1,
        )
        sock.settimeout(1)
        return sock


class TcpClientServerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        with ClientSession._state_lock:
            ClientSession.scans = {}
            ClientSession.next_scan_id = 1

        self.tmpdir = tempfile.TemporaryDirectory()
        self.upload_dir_patcher = patch(
            "server.client_session.UPLOAD_DIR",
            Path(self.tmpdir.name),
        )
        self.upload_dir_patcher.start()

    def tearDown(self) -> None:
        self.upload_dir_patcher.stop()
        self.tmpdir.cleanup()

    def test_upload_list_hashes_and_quit_over_tcp(self) -> None:
        filename = "programa de teste.elf"
        filename_bytes = filename.encode("utf-8")
        payload = b"\x7fELF" + bytes(60)

        with patch("builtins.print"):
            with TcpSessionHarness() as server:
                with server.connect() as client:
                    send_command(client, "/CONNECT")
                    self.assertEqual(read_response(client), "OK CONNECTED")

                    send_command(
                        client,
                        f"/UPLOAD {len(filename_bytes)} {len(payload)}",
                    )
                    self.assertEqual(read_response(client), "OK READY")
                    client.sendall(filename_bytes + payload)

                    upload_response = read_response(client)
                    self.assertIn("OK UPLOADED scan_id=1", upload_response)
                    self.assertIn(f"filename={filename}", upload_response)

                    send_command(client, "/LIST")
                    listing = read_response(client)
                    self.assertIn(f"1 | {filename}", listing)

                    send_command(client, "/HASHES 1")
                    hashes = read_response(client)
                    self.assertIn("OK HASHES FOR SCAN 1", hashes)
                    self.assertIn(
                        f"MD5: {hashlib.md5(payload).hexdigest()}",
                        hashes,
                    )
                    self.assertIn(
                        f"SHA-256: {hashlib.sha256(payload).hexdigest()}",
                        hashes,
                    )

                    send_command(client, "/QUIT")
                    self.assertEqual(read_response(client), "OK BYE")

        stored_path = Path(self.tmpdir.name) / f"1_{filename}"
        self.assertEqual(stored_path.read_bytes(), payload)

    def test_rejects_non_elf_and_keeps_protocol_synchronized(self) -> None:
        filename_bytes = b"not-elf.bin"
        payload = b"plain text payload"

        with patch("builtins.print"):
            with TcpSessionHarness() as server:
                with server.connect() as client:
                    send_command(client, "/CONNECT")
                    self.assertEqual(read_response(client), "OK CONNECTED")

                    send_command(
                        client,
                        f"/UPLOAD {len(filename_bytes)} {len(payload)}",
                    )
                    self.assertEqual(read_response(client), "OK READY")
                    client.sendall(filename_bytes + payload)
                    self.assertEqual(
                        read_response(client),
                        "ERR UNSUPPORTED_FORMAT expected=ELF",
                    )

                    send_command(client, "/LIST")
                    listing = read_response(client)
                    self.assertIn("Nenhum arquivo analisado", listing)

                    send_command(client, "/QUIT")
                    self.assertEqual(read_response(client), "OK BYE")

    def test_idle_session_receives_timeout_error(self) -> None:
        with patch("builtins.print"):
            with TcpSessionHarness(timeout_seconds=0.05) as server:
                with server.connect() as client:
                    self.assertEqual(read_response(client), "ERR TIMEOUT")


if __name__ == "__main__":
    unittest.main()
