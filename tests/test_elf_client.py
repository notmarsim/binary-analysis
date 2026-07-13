import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from elf_client import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    handle_local_upload,
    parse_args,
    parse_port,
)
from protocol_limits import MAX_FILE_SIZE_BYTES


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
        self.assertIsNone(args.file)

    def test_accepts_custom_endpoint_and_file(self) -> None:
        args = parse_args(
            ["--host", "192.168.1.20", "--port", "9100", "/bin/ls"]
        )

        self.assertEqual(args.host, "192.168.1.20")
        self.assertEqual(args.port, 9100)
        self.assertEqual(str(args.file), "/bin/ls")


class RecordingSocket:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)


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


if __name__ == "__main__":
    unittest.main()
