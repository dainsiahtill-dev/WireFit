"""Independent fixed bytes and preservation checks, without CPU/native execution."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


class NodeRecordTests(unittest.TestCase):
    def function(self):
        source = HERE / 'model.py'
        self.assertTrue(source.is_file(), 'Independent node-record model is not implemented')
        if 'node_record_test_model' not in sys.modules:
            spec = importlib.util.spec_from_file_location('node_record_test_model', source)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        return sys.modules['node_record_test_model'].patch_node_record

    def test_internal_record_has_fixed_ieee_bytes_and_zero_flag(self):
        actual = self.function()(b'\xa5' * 40, 0, 1, 2, 3, 3)
        expected = bytes.fromhex('000000000000f03f00000000000000400000803f00000040') + b'\xa5' * 4 + b'\x00' + b'\xa5' * 11
        self.assertEqual(actual, expected)

    def test_origin_corner_fixed_zero_values_and_three_flag(self):
        actual = self.function()(b'\x6d' * 40, 0, 0, 0, 2, 2)
        self.assertEqual(actual, b'\x00' * 24 + b'\x6d' * 4 + b'\x03' + b'\x6d' * 11)

    def test_bottom_right_corner_has_fixed_two_three_bytes(self):
        actual = self.function()(b'\xa5' * 40, 0, 2, 3, 2, 3)
        expected = bytes.fromhex('000000000000004000000000000008400000004000004040') + b'\xa5' * 4 + b'\x03' + b'\xa5' * 11
        self.assertEqual(actual, expected)

    def test_left_edge_is_not_a_corner(self):
        self.assertEqual(self.function()(b'\xaa' * 40, 0, 0, 1, 2, 2)[28], 0)

    def test_top_edge_is_not_a_corner(self):
        self.assertEqual(self.function()(b'\xaa' * 40, 0, 1, 0, 2, 2)[28], 0)

    def test_top_right_and_bottom_left_are_corners(self):
        fn = self.function()
        self.assertEqual(fn(b'\xaa' * 40, 0, 2, 0, 2, 2)[28], 3)
        self.assertEqual(fn(b'\xaa' * 40, 0, 0, 2, 2, 2)[28], 3)

    def test_other_records_and_unknown_fields_are_preserved(self):
        storage = bytes(range(120)); actual = self.function()(storage, 1, 1, 1, 2, 2)
        self.assertEqual(actual[:40], storage[:40])
        self.assertEqual(actual[80:], storage[80:])
        self.assertEqual(actual[64:68], storage[64:68])
        self.assertEqual(actual[69:80], storage[69:80])

    def test_maximum_id_288_and_capacity_289(self):
        storage = b'\x5a' * (40 * 289); actual = self.function()(storage, 288, 16, 16, 16, 16)
        self.assertEqual(actual[:288 * 40], storage[:288 * 40])
        self.assertEqual(struct.unpack_from('<ddff', actual, 288 * 40), (16.0, 16.0, 16.0, 16.0))
        self.assertEqual(actual[288 * 40 + 28], 3)
        self.assertEqual(len(actual), len(storage))

    def test_source_bytes_unchanged_and_result_exact_bytes_type(self):
        storage = b'\x82' * 80; before = storage
        actual = self.function()(storage, 1, 2, 1, 2, 2)
        self.assertEqual(storage, before)
        self.assertIs(type(actual), bytes)

    def test_storage_must_be_exact_bytes(self):
        fn = self.function()
        for storage in [bytearray(40), memoryview(bytes(40)), 'x' * 40, [0] * 40]:
            with self.subTest(storage=type(storage).__name__), self.assertRaises(ValueError): fn(storage, 0, 0, 0, 2, 2)

    def test_storage_shape_and_capacity_are_bounded(self):
        fn = self.function()
        for storage in [b'', bytes(39), bytes(41), bytes(40 * 290)]:
            with self.subTest(length=len(storage)), self.assertRaises(ValueError): fn(storage, 0, 0, 0, 2, 2)

    def test_every_integer_field_rejects_bool_or_float(self):
        fn = self.function()
        for index in range(5):
            for value in [True, False, 1.0]:
                args = [0, 1, 1, 2, 2]; args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError): fn(bytes(40), *args)

    def test_dimensions_and_coordinates_have_strict_bounds(self):
        fn = self.function()
        for args in [(0, 0, 0, 1, 2), (0, 0, 0, 17, 2), (0, 0, 0, 2, 1), (0, 0, 0, 2, 17),
                     (0, -1, 0, 2, 2), (0, 3, 0, 2, 2), (0, 0, -1, 2, 2), (0, 0, 3, 2, 2)]:
            with self.subTest(args=args), self.assertRaises(ValueError): fn(bytes(40), *args)

    def test_node_id_must_fit_actual_storage(self):
        fn = self.function()
        for node_id in [-1, 1, 288]:
            with self.subTest(node_id=node_id), self.assertRaises(ValueError): fn(bytes(40), node_id, 0, 0, 2, 2)

    def test_repeated_patch_is_idempotent(self):
        fn = self.function(); first = fn(b'\xaa' * 40, 0, 1, 1, 2, 2)
        self.assertEqual(fn(first, 0, 1, 1, 2, 2), first)


if __name__ == '__main__': unittest.main(verbosity=2)
