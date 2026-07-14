import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, call, patch

try:
    import ssdeep  # noqa: F401
except ModuleNotFoundError:
    ssdeep_stub = ModuleType("ssdeep")
    ssdeep_stub.compare = lambda _left, _right: 0
    sys.modules["ssdeep"] = ssdeep_stub

from protocol_limits import (
    MAX_FILE_SIZE_BYTES,
    MAX_FILENAME_SIZE_BYTES,
    SERVER_SESSION_TIMEOUT_SECONDS,
)
from server.client_session import ClientSession


class RecordingSocket:
    def __init__(self) -> None:
        self.sent = bytearray()
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def close(self) -> None:
        self.closed = True

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def response_text(self) -> str:
        return self.sent.decode("utf-8")


class SessionTimeoutTests(unittest.TestCase):
    def test_configures_timeout_on_client_socket(self) -> None:
        sock = RecordingSocket()

        ClientSession(sock, ("127.0.0.1", 12345))

        self.assertEqual(sock.timeout, SERVER_SESSION_TIMEOUT_SECONDS)


class ClientSessionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        ClientSession.scans = {}
        ClientSession.next_scan_id = 1
        self.socket = RecordingSocket()
        self.session = ClientSession(self.socket, ("127.0.0.1", 12345))
        self.session.connected = True


class UploadSizeValidationTests(ClientSessionTestCase):
    @patch("server.client_session.recv_exactly")
    def test_rejects_non_numeric_size_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "6", "abc"])

        self.assertTrue(keep_session)
        self.assertIn("ERR INVALID_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_zero_size_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "6", "0"])

        self.assertTrue(keep_session)
        self.assertIn("ERR INVALID_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_negative_size_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "6", "-1"])

        self.assertTrue(keep_session)
        self.assertIn("ERR INVALID_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_size_above_limit_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        oversized = MAX_FILE_SIZE_BYTES + 1

        keep_session = self.session.handle_upload(
            ["/UPLOAD", "6", str(oversized)]
        )

        self.assertTrue(keep_session)
        self.assertIn("ERR FILE_TOO_LARGE", self.socket.response_text())
        self.assertIn(
            f"max_bytes={MAX_FILE_SIZE_BYTES}", self.socket.response_text()
        )
        recv_exactly.assert_not_called()


class UploadFilenameFramingTests(ClientSessionTestCase):
    @patch("server.client_session.recv_exactly")
    def test_rejects_upload_before_connect_without_reading_payload(
        self, recv_exactly: Mock
    ) -> None:
        self.session.connected = False

        keep_session = self.session.handle_upload(["/UPLOAD", "6", "3"])

        self.assertTrue(keep_session)
        self.assertIn("ERR NOT_CONNECTED", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_invalid_header_without_consuming_payload(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "6"])

        self.assertTrue(keep_session)
        self.assertIn("ERR INVALID_UPLOAD", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_filename_size_above_limit(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(
            ["/UPLOAD", str(MAX_FILENAME_SIZE_BYTES + 1), "3"]
        )

        self.assertTrue(keep_session)
        self.assertIn("ERR INVALID_FILENAME_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.ElfParser")
    @patch("server.client_session.recv_exactly")
    def test_accepts_filename_with_spaces(
        self, recv_exactly: Mock, elf_parser: Mock
    ) -> None:
        filename = "meu programa.elf"
        filename_bytes = filename.encode("utf-8")
        file_bytes = b"ELF"
        recv_exactly.side_effect = [filename_bytes, file_bytes]
        parser = elf_parser.return_value
        parser.parse_header_with_binutils.return_value = {"Type": "EXEC"}
        parser.calculate_hashes.return_value = {"SHA256": "hash"}

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("server.client_session.UPLOAD_DIR", Path(tmpdir)):
                keep_session = self.session.handle_upload(
                    ["/UPLOAD", str(len(filename_bytes)), str(len(file_bytes))]
                )
                stored_path = Path(tmpdir) / f"1_{filename}"
                self.assertEqual(stored_path.read_bytes(), file_bytes)

        self.assertTrue(keep_session)
        self.assertEqual(ClientSession.scans[1].filename, filename)
        self.assertIn("OK READY", self.socket.response_text())
        self.assertIn(
            f"OK UPLOADED scan_id=1 filename={filename}",
            self.socket.response_text(),
        )
        self.assertEqual(
            recv_exactly.call_args_list,
            [call(self.socket, len(filename_bytes)), call(self.socket, 3)],
        )

    @patch("server.client_session.recv_exactly", return_value=b"../evil")
    def test_rejects_path_like_filename_and_closes_before_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "7", "3"])

        self.assertFalse(keep_session)
        self.assertIn("OK READY", self.socket.response_text())
        self.assertIn("ERR INVALID_FILENAME", self.socket.response_text())
        recv_exactly.assert_called_once_with(self.socket, 7)


if __name__ == "__main__":
    unittest.main()
