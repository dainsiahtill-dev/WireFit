"""Validation tests are independent of native IDA and licensing."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

specification = importlib.util.spec_from_file_location("owned_stdio", Path(__file__).with_name("owned_stdio.py"))
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)


class OwnedArgumentsTests(unittest.TestCase):
    def test_regular_file_and_sibling_database(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.exe"
            source.write_bytes(b"MZ")
            self.assertEqual(module.checked_input(str(source)), source.resolve())
            self.assertEqual(module.checked_database(str(source.with_suffix(".i64")), source.resolve()), source.with_suffix(".i64").resolve())

    def test_directory_empty_and_oversized_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.exe"
            with self.assertRaises(ValueError):
                module.checked_input(directory)
            source.write_bytes(b"")
            with self.assertRaises(ValueError):
                module.checked_input(str(source))
            with source.open("wb") as stream:
                stream.truncate(module.MAX_INPUT_BYTES + 1)
            with self.assertRaises(ValueError):
                module.checked_input(str(source))

    def test_existing_wrong_suffix_and_external_database_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as other:
            source = Path(directory) / "source.exe"
            source.write_bytes(b"MZ")
            existing = Path(directory) / "existing.i64"
            existing.write_bytes(b"owned elsewhere")
            for database in [existing, source, Path(other) / "analysis.i64"]:
                with self.assertRaises(ValueError):
                    module.checked_database(str(database), source.resolve())

    def test_symlink_input_rejected_when_available(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.exe"
            source.write_bytes(b"MZ")
            link = Path(directory) / "link.exe"
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest("Creating symlinks is unavailable for this Windows token")
            with self.assertRaises(ValueError):
                module.checked_input(str(link))

    def test_hardlink_input_and_existing_sidecar_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.exe"
            source.write_bytes(b"MZ")
            link = Path(directory) / "hardlink.exe"
            link.hardlink_to(source)
            with self.assertRaises(ValueError):
                module.checked_input(str(source))
            sidecar = Path(directory) / "analysis.id0"
            sidecar.write_bytes(b"unrelated")
            with self.assertRaises(ValueError):
                module.checked_database(str(sidecar.with_suffix(".i64")), source.resolve())


if __name__ == "__main__":
    unittest.main()
