"""Pure protocol/FS tests. They never import Unicorn or execute body instructions."""
import hashlib
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


class ReplayBoundaryTests(unittest.TestCase):
    def module(self):
        source = HERE / 'replay.py'
        self.assertTrue(source.is_file(), 'Bounded replay runner is not implemented')
        if 'node_record_replay_test' not in sys.modules:
            spec = importlib.util.spec_from_file_location('node_record_replay_test', source)
            value = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = value
            spec.loader.exec_module(value)
        return sys.modules['node_record_replay_test']

    def test_exact_body_pin_and_closed_instruction_inventory(self):
        m = self.module()
        self.assertEqual(len(m.BODY), 104)
        self.assertEqual(hashlib.sha256(m.BODY).hexdigest(), 'd7daa514e39357d058792f132bfbc084f1b03d8f67a17668af8839eb8da6aa38')
        self.assertEqual(m.BODY[-3:], bytes.fromhex('c20c00'))
        intervals = sorted(m.INSTRUCTIONS.items())
        self.assertEqual(len(intervals), 38)
        self.assertEqual([address + size for address, size in intervals[:-1]], [address for address, _ in intervals[1:]])
        self.assertEqual(intervals[0][0], 0x480230)
        self.assertEqual(sum(m.INSTRUCTIONS.values()), 104)

    def test_fixed_raw_image_hash_is_required_before_extraction(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'image identity'):
            m.extract_body(b'MZ' + bytes(1024))

    def test_cases_require_frozen_model_and_cover_geometry_and_max_id(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'model'):
            m.build_cases('0' * 64)
        cases = m.build_cases(m.MODEL_SHA256)
        self.assertLessEqual(len(cases), 128)
        self.assertGreaterEqual(len(cases), 20)
        self.assertEqual(len({c['id'] for c in cases}), len(cases))
        self.assertTrue(any(c['node_id'] == 288 and c['capacity'] == 289 for c in cases))
        for width, height in [(2, 2), (3, 2), (16, 16)]:
            subset = [c for c in cases if (c['width'], c['height']) == (width, height)]
            self.assertTrue(any(c['x'] in (0, width) and c['y'] in (0, height) for c in subset))
            self.assertTrue(any((c['x'] in (0, width)) != (c['y'] in (0, height)) for c in subset))
            self.assertTrue(any(0 < c['x'] < width and 0 < c['y'] < height for c in subset))

    def test_raw_and_pe_offsets_are_distinct_for_fixed_source(self):
        m = self.module()
        self.assertEqual(m.IMAGE_RAW_OFFSET, 0x7f630)
        self.assertNotEqual(m.IMAGE_RAW_OFFSET, m.ENTRY - 0x400000)

    def test_path_rejects_traversal_ads_and_reserved_aliases(self):
        m = self.module()
        for name in ['../x', 'x/../y', 'foo:stream', 'CON', 'NUL.txt', 'file.', 'file ', 'x\x00y']:
            with self.subTest(name=name), self.assertRaises(ValueError): m.checked_path(name)

    def test_stable_read_rejects_real_hardlink_without_touching_bytes(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'source'; source.write_bytes(b'observed')
            alias = Path(folder) / 'alias'; os.link(source, alias)
            with self.assertRaises(ValueError): m.stable_read(source, 64)
            self.assertEqual(source.read_bytes(), b'observed')

    def test_stable_read_accepts_pinned_zero_byte_dependency(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'empty'; source.write_bytes(b'')
            actual = m.stable_read(source, 1)
            self.assertEqual(len(actual), 0)
            self.assertEqual(hashlib.sha256(actual).hexdigest(), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def dependency_fixture(self, root):
        pins = json.loads((HERE / 'unicorn-pins.json').read_text(encoding='utf-8'))
        installed = HERE.parents[1] / '.tools' / 'analysis' / 'unicorn-python'
        for row in pins['files']:
            destination = root / row['file']; destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((installed / row['file']).read_bytes())
        return pins['files']

    def test_clean_stage_contains_exact_pins_and_cannot_resolve_source_extension_shadow(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'stage_unicorn'), 'Pinned dependency staging is not implemented')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'source'; runtime = root / 'runtime'
            pins = self.dependency_fixture(source)
            shadow = source / 'unicorn' / ('__init__' + importlib.machinery.EXTENSION_SUFFIXES[0])
            shadow.write_bytes(b'not executed')
            loaders = ((importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES),
                       (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES))
            untrusted_spec = importlib.machinery.FileFinder(str(source), *loaders).find_spec('unicorn')
            self.assertEqual(Path(untrusted_spec.origin), shadow)
            evidence = m.stage_unicorn(source, runtime)
            safe_spec = importlib.machinery.FileFinder(str(runtime), *loaders).find_spec('unicorn')
            self.assertEqual(Path(safe_spec.origin), runtime / 'unicorn' / '__init__.py')
            self.assertIs(safe_spec.loader.__class__, importlib.machinery.SourceFileLoader)
            self.assertEqual({path.relative_to(runtime).as_posix() for path in runtime.rglob('*') if path.is_file()}, {row['file'] for row in pins})
            for category in ('source_files', 'staged_files'):
                self.assertEqual(len(evidence[category]), 23)
                self.assertTrue(any(row['size_bytes'] == 0 for row in evidence[category]))
                for row in evidence[category]:
                    self.assertEqual(hashlib.sha256(Path(row['path']).read_bytes()).hexdigest(), row['sha256'])
            self.assertTrue(shadow.is_file())

    def test_bad_dependency_pin_rejects_before_stage_creation(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'stage_unicorn'), 'Pinned dependency staging is not implemented')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'source'; runtime = root / 'runtime'
            self.dependency_fixture(source)
            (source / 'unicorn' / '__init__.py').write_bytes(b'untrusted')
            with self.assertRaisesRegex(ValueError, 'Pinned Unicorn file mismatch'):
                m.stage_unicorn(source, runtime)
            self.assertFalse(runtime.exists())

    def test_unregistered_file_in_stage_is_rejected_before_any_import(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'stage_unicorn'), 'Pinned dependency staging is not implemented')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'source'; runtime = root / 'runtime'
            self.dependency_fixture(source); m.stage_unicorn(source, runtime)
            (runtime / 'unicorn' / '__init__.pyd').write_bytes(b'not executed')
            with patch.object(m.importlib, 'import_module', side_effect=AssertionError('Import must not occur')) as importer:
                with self.assertRaisesRegex(ValueError, 'inventory'):
                    m.load_unicorn(runtime, root / 'unused-pycache')
                self.assertEqual(importer.call_count, 0)

    def test_retained_handle_read_rejects_real_path_replacement(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'source'; source.write_bytes(b'first')
            replacement = Path(folder) / 'replacement'; replacement.write_bytes(b'other')
            original = m.check_chain; calls = 0
            def observed(path):
                nonlocal calls
                calls += 1
                result = original(path)
                if calls == 2:
                    # Windows denies renaming over Python's open reader. The
                    # real replacement occurs just after HANDLE close and
                    # before the final path identity check instead.
                    os.replace(replacement, source)
                return result
            with patch.object(m, 'check_chain', observed), self.assertRaisesRegex(ValueError, 'changed'):
                m.stable_read(source, 64)

    def test_wrong_flag_and_coordinate_mutants_are_rejected(self):
        m = self.module()
        expected = bytes(24) + b'\xa5' * 4 + b'\x03' + b'\xa5' * 11
        self.assertTrue(m.compare_storage(expected, expected)['matched'])
        wrong_flag = bytearray(expected); wrong_flag[28] = 0
        wrong_coordinate = bytearray(expected); struct.pack_into('<d', wrong_coordinate, 0, 1)
        self.assertFalse(m.compare_storage(bytes(wrong_flag), expected)['matched'])
        self.assertFalse(m.compare_storage(bytes(wrong_coordinate), expected)['matched'])
        self.assertFalse(m.compare_storage(expected[:-1], expected)['matched'])

    def test_unknown_field_or_neighbor_mutation_is_detected(self):
        m = self.module(); expected = b'\xa5' * 80
        for index in [24, 29, 39, 40, 79]:
            actual = bytearray(expected); actual[index] ^= 1
            self.assertFalse(m.compare_storage(bytes(actual), expected)['matched'])

    def test_cpu_boundary_rejects_unknown_pc_and_wrong_instruction_size(self):
        m = self.module(); boundary = m.CpuBoundary(0x30001000, 40, 0, 0x50001f00)
        boundary.check_code(0x480230, 4)
        for address, size in [(0x480231, 3), (0x480230, 5), (0x480298, 1), (0x12345678, 1)]:
            with self.subTest(address=address), self.assertRaises(ValueError): boundary.check_code(address, size)

    def test_cpu_boundary_accepts_only_observed_record_fields_and_push_slot(self):
        m = self.module(); base = 0x30001000; stack = 0x50001f00
        boundary = m.CpuBoundary(base, 80, 1, stack)
        for offset, size in [(40, 8), (48, 8), (56, 4), (60, 4), (68, 1)]: boundary.check_write(base + offset, size)
        boundary.check_write(stack - 4, 4)
        for address, size in [(base, 8), (base + 64, 4), (base + 69, 1), (stack - 8, 4), (base + 68, 2)]:
            with self.subTest(address=address), self.assertRaises(ValueError): boundary.check_write(address, size)

    def test_x87_roundtrip_records_actual_values_and_rejects_unsupported_state(self):
        m = self.module()
        class RegisterCpu:
            def __init__(self, ignore=False): self.values = {}; self.ignore = ignore
            def reg_write(self, key, value): self.values[key] = 0 if self.ignore else value
            def reg_read(self, key): return self.values[key]
        keys = {'control': 246, 'status': 31, 'tag': 247}
        self.assertEqual(m.initialize_x87(RegisterCpu(), keys), {'control': 0x37f, 'status': 0, 'tag': 0xffff, 'top': 0})
        with self.assertRaisesRegex(ValueError, 'x87'):
            m.initialize_x87(RegisterCpu(True), keys)

    def invoke(self, *args):
        result = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-I', '-S', str(HERE / 'replay.py'), *args],
                                capture_output=True, timeout=10)
        import json
        return result, json.loads(result.stdout.decode('utf-8', errors='strict'))

    def test_real_cli_wrong_image_hash_creates_no_output_or_cpu_rows(self):
        self.module()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); image = root / 'bad.bin'; image.write_bytes(b'not the pinned dump')
            output = root / 'output'
            child, result = self.invoke('--module-path', str(root), '--image', str(image), '--out', str(output))
            self.assertEqual(child.returncode, 1)
            self.assertEqual(result['status'], 'failed')
            self.assertIn('image identity', result['error']['message'])
            self.assertEqual(result['rows'], [])
            self.assertFalse(output.exists())
            self.assertEqual(child.stderr, b'')

    def test_real_cli_existing_output_is_unchanged(self):
        self.module()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); output = root / 'output'; output.mkdir()
            sentinel = output / 'sentinel'; sentinel.write_bytes(b'original')
            child, result = self.invoke('--module-path', str(root), '--image', str(root / 'unused'), '--out', str(output))
            self.assertEqual(child.returncode, 1)
            self.assertIn('already exists', result['error']['message'])
            self.assertEqual(list(output.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b'original')

    def test_real_cli_duplicate_option_is_rejected_before_filesystem_mutation(self):
        self.module()
        child, result = self.invoke('--module-path', 'first', '--module-path', 'second', '--image', 'unused', '--out', 'unused')
        self.assertEqual(child.returncode, 1)
        self.assertIn('Repeated option', result['error']['message'])
        self.assertEqual(result['rows'], [])


if __name__ == '__main__': unittest.main(verbosity=2)
