import argparse
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from elf_client import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    handle_local_upload,
    parse_args,
    run_interactive,
    parse_port,
)
from protocol_limits import (
    CONNECT_TIMEOUT_SECONDS,
    MAX_FILE_SIZE_BYTES,
    SOCKET_IO_TIMEOUT_SECONDS,
)


class ParsePortTests(unittest.TestCase):
    def test_accepts_valid_port(self) -> None:
        self.assertEqual(parse_port("9000"), 9000)

    def test_rejects_port_below_valid_range(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port("0")

    def test_rejects_port_above_valid_range(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port("65536")

    def test_rejects_non_numeric_port(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_port("abc")


class ParseArgumentsTests(unittest.TestCase):
    def test_uses_default_endpoint(self) -> None:
        args = parse_args([])

        self.assertEqual(args.host, DEFAULT_HOST)
        self.assertEqual(args.port, DEFAULT_PORT)

    def test_accepts_custom_endpoint(self) -> None:
        args = parse_args(["--host", "192.168.1.20", "--port", "9100"])

        self.assertEqual(args.host, "192.168.1.20")
        self.assertEqual(args.port, 9100)

    def test_rejects_positional_upload_path(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as context:
                parse_args(["/bin/ls"])

        self.assertEqual(context.exception.code, 2)


class RecordingSocket:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


class ContextSocket(RecordingSocket):
    def __init__(self) -> None:
        super().__init__()
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout


class ClientTimeoutTests(unittest.TestCase):
    @patch("elf_client.read_response", return_value="OK BYE")
    @patch("builtins.input", return_value="/QUIT")
    @patch("elf_client.socket.create_connection")
    def test_configures_connect_and_io_timeouts(
        self, create_connection, _input, _read_response
    ) -> None:
        sock = ContextSocket()
        create_connection.return_value = sock

        with patch("builtins.print"):
            run_interactive("127.0.0.1", 9000)

        create_connection.assert_called_once_with(
            ("127.0.0.1", 9000), timeout=CONNECT_TIMEOUT_SECONDS
        )
        self.assertEqual(sock.timeout, SOCKET_IO_TIMEOUT_SECONDS)


class LocalUploadValidationTests(unittest.TestCase):
    def test_rejects_empty_file_before_sending(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "empty.bin"
            path.touch()
            sock = RecordingSocket()

            with patch("builtins.print"):
                uploaded = handle_local_upload(sock, f"/UPLOAD {path}")

        self.assertFalse(uploaded)
        self.assertEqual(sock.sent, b"")

    def test_rejects_file_above_protocol_limit_before_sending(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "oversized.bin"
            with path.open("wb") as file_obj:
                file_obj.truncate(MAX_FILE_SIZE_BYTES + 1)
            sock = RecordingSocket()

            with patch("builtins.print"):
                uploaded = handle_local_upload(sock, f"/UPLOAD {path}")

        self.assertFalse(uploaded)
        self.assertEqual(sock.sent, b"")

    @patch("elf_client.read_response", return_value="OK READY")
    def test_sends_filename_with_spaces_after_server_is_ready(
        self, read_response
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "meu programa.elf"
            path.write_bytes(b"ELF")
            sock = RecordingSocket()

            uploaded = handle_local_upload(sock, f"/UPLOAD {path}")

        filename_bytes = path.name.encode("utf-8")
        expected = (
            f"/UPLOAD {len(filename_bytes)} 3\n".encode("utf-8")
            + filename_bytes
            + b"ELF"
        )
        self.assertTrue(uploaded)
        self.assertEqual(sock.sent, expected)
        read_response.assert_called_once_with(sock)

    @patch("elf_client.read_response", return_value="ERR NOT_CONNECTED")
    def test_does_not_send_payload_when_server_rejects_metadata(
        self, read_response
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.elf"
            path.write_bytes(b"ELF")
            sock = RecordingSocket()

            with patch("builtins.print"):
                uploaded = handle_local_upload(sock, f"/UPLOAD {path}")

        expected_header = f"/UPLOAD {len(path.name.encode('utf-8'))} 3\n".encode()
        self.assertFalse(uploaded)
        self.assertEqual(sock.sent, expected_header)
        read_response.assert_called_once_with(sock)


if __name__ == "__main__":
    unittest.main()
