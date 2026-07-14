import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis.elf_parser import ElfParser


class HashCalculationTests(unittest.TestCase):
    @patch(
        "analysis.elf_parser.hashing.calculate_fuzzy_hash",
        return_value="3:sample:fuzzy",
    )
    def test_calculates_all_reported_hashes(self, calculate_fuzzy_hash) -> None:
        payload = b"binary-analysis"

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.elf"
            path.write_bytes(payload)

            hashes = ElfParser(path).calculate_hashes()

        self.assertEqual(hashes["MD5"], hashlib.md5(payload).hexdigest())
        self.assertEqual(hashes["SHA1"], hashlib.sha1(payload).hexdigest())
        self.assertEqual(hashes["SHA256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(hashes["SSDEEP"], "3:sample:fuzzy")
        calculate_fuzzy_hash.assert_called_once_with(payload)


if __name__ == "__main__":
    unittest.main()
