import unittest
from unittest.mock import Mock, patch

from protocol_limits import MAX_FILE_SIZE_BYTES
from server.client_session import ClientSession


class RecordingSocket:
    def __init__(self) -> None:
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def response_text(self) -> str:
        return self.sent.decode("utf-8")


class UploadSizeValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.socket = RecordingSocket()
        self.session = ClientSession(self.socket, ("127.0.0.1", 12345))
        self.session.connected = True

    @patch("server.client_session.recv_exactly")
    def test_rejects_non_numeric_size_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "sample", "abc"])

        self.assertFalse(keep_session)
        self.assertIn("ERR INVALID_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_zero_size_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "sample", "0"])

        self.assertFalse(keep_session)
        self.assertIn("ERR INVALID_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_negative_size_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        keep_session = self.session.handle_upload(["/UPLOAD", "sample", "-1"])

        self.assertFalse(keep_session)
        self.assertIn("ERR INVALID_SIZE", self.socket.response_text())
        recv_exactly.assert_not_called()

    @patch("server.client_session.recv_exactly")
    def test_rejects_size_above_limit_without_reading_body(
        self, recv_exactly: Mock
    ) -> None:
        oversized = MAX_FILE_SIZE_BYTES + 1

        keep_session = self.session.handle_upload(
            ["/UPLOAD", "sample", str(oversized)]
        )

        self.assertFalse(keep_session)
        self.assertIn("ERR FILE_TOO_LARGE", self.socket.response_text())
        self.assertIn(
            f"max_bytes={MAX_FILE_SIZE_BYTES}", self.socket.response_text()
        )
        recv_exactly.assert_not_called()


if __name__ == "__main__":
    unittest.main()
