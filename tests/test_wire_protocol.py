import socket
import unittest

from wire_protocol import (
    ProtocolError,
    decode_upload_filename,
    encode_upload_filename,
    read_command,
    read_response,
    send_command,
    send_response,
)


class ProtocolFramingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right = socket.socketpair()

    def tearDown(self) -> None:
        self.left.close()
        self.right.close()

    def test_command_round_trip(self) -> None:
        send_command(self.left, "/INFO 7")

        self.assertEqual(read_command(self.right), "/INFO 7")

    def test_response_preserves_embedded_blank_lines(self) -> None:
        payload = "primeira linha\n\nterceira linha\n"

        send_response(self.left, payload)

        self.assertEqual(read_response(self.right), payload)

    def test_response_length_uses_utf8_bytes(self) -> None:
        send_response(self.left, "á")

        self.assertEqual(self.right.recv(13), b"RESPONSE 2\n\xc3\xa1")

    def test_rejects_malformed_response_header(self) -> None:
        self.left.sendall(b"OK 4\ntest")

        with self.assertRaises(ProtocolError):
            read_response(self.right)

    def test_rejects_incomplete_response_payload(self) -> None:
        self.left.sendall(b"RESPONSE 5\nabc")
        self.left.shutdown(socket.SHUT_WR)

        with self.assertRaises(ProtocolError):
            read_response(self.right)

    def test_rejects_command_with_line_break(self) -> None:
        with self.assertRaises(ValueError):
            send_command(self.left, "/LIST\n/QUIT")

    def test_upload_filename_supports_spaces_and_utf8(self) -> None:
        filename = "análise binária.elf"

        encoded = encode_upload_filename(filename)

        self.assertEqual(decode_upload_filename(encoded), filename)
        self.assertEqual(len(encoded), len(filename.encode("utf-8")))

    def test_rejects_path_like_upload_filename(self) -> None:
        with self.assertRaises(ValueError):
            encode_upload_filename("../sample.elf")

    def test_rejects_non_utf8_upload_filename(self) -> None:
        with self.assertRaises(ProtocolError):
            decode_upload_filename(b"\xff")


if __name__ == "__main__":
    unittest.main()
