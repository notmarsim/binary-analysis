import argparse
import unittest

from elf_client import DEFAULT_HOST, DEFAULT_PORT, parse_args, parse_port


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


if __name__ == "__main__":
    unittest.main()
