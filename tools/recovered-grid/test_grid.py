"""Fixed expectations and real stdlib CLI tests; no original candidate imported."""
from dataclasses import FrozenInstanceError
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def canonical_case(**changes):
    return {"id": "small-2", "width": 2, "height": 2, "node_stride": 3,
            "source_stride": 2, "labels": [0, 0, 0, 0], **changes}


class ModelTests(unittest.TestCase):
    def model(self):
        file = HERE / "model.py"
        self.assertTrue(file.is_file(), "Independent recovered model is not implemented")
        if "recovered_grid_test_model" not in sys.modules:
            spec = importlib.util.spec_from_file_location("recovered_grid_test_model", file)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        return sys.modules["recovered_grid_test_model"]

    def test_uniform_2x2_fixed_expected_nodes_and_count(self):
        result = self.model().number_grid([7, 7, 7, 7], 2, 2, 3)
        self.assertEqual(result.nodes, (0, 6, 3, 1, -1, 4, 2, 7, 5))
        self.assertEqual(result.node_count, 8)

    def test_nonuniform_2x2_fixed_expected_nodes_and_count(self):
        result = self.model().number_grid([0, 0, 0, 1], 2, 2, 3)
        self.assertEqual(result.nodes, (0, 6, 3, 1, 8, 4, 2, 7, 5))
        self.assertEqual(result.node_count, 9)

    def test_padding_is_zero_and_does_not_receive_numbers(self):
        result = self.model().number_grid([4, 4, 4, 4], 2, 2, 5)
        self.assertEqual(result.nodes, (0, 6, 3, 0, 0, 1, -1, 4, 0, 0, 2, 7, 5, 0, 0))
        self.assertEqual(result.node_count, 8)

    def test_signed_extremes_are_labels_without_arithmetic_conversion(self):
        result = self.model().number_grid([-(1 << 31), (1 << 31) - 1, -(1 << 31), (1 << 31) - 1], 2, 2, 3)
        self.assertEqual(result.nodes, (0, 6, 3, 1, 8, 4, 2, 7, 5))
        self.assertEqual(result.node_count, 9)

    def test_non_square_grid_preserves_boundary_order_then_interior_row_order(self):
        result = self.model().number_grid([0, 0, 0, 0, 1, 1], 3, 2, 4)
        self.assertEqual(result.nodes, (0, 6, 7, 3, 1, 10, 11, 4, 2, 8, 9, 5))
        self.assertEqual(result.node_count, 12)

    def test_input_is_not_mutated_and_result_is_frozen(self):
        labels = [-1, 0, 1, 1]; before = labels.copy()
        result = self.model().number_grid(labels, 2, 2, 3)
        self.assertEqual(labels, before)
        self.assertIsInstance(result.nodes, tuple)
        with self.assertRaises(FrozenInstanceError): result.node_count = 42

    def test_maximum_uniform_grid_has_64_boundary_nodes(self):
        result = self.model().number_grid([9] * 256, 16, 16, 24)
        self.assertEqual(result.node_count, 64)
        self.assertEqual(len(result.nodes), 408)
        self.assertEqual(result.nodes.count(-1), 225)
        self.assertEqual(max(result.nodes), 63)

    def test_dimensions_and_stride_reject_bools_floats_and_bounds(self):
        number = self.model().number_grid
        for width, height, stride in [(True, 2, 3), (2, False, 3), (2, 2, True), (2.0, 2, 3),
                                      (1, 2, 3), (17, 2, 18), (2, 1, 3), (2, 17, 3), (2, 2, 2), (2, 2, 11)]:
            with self.subTest(args=(width, height, stride)), self.assertRaises(ValueError): number([0] * 4, width, height, stride)

    def test_labels_require_dense_exact_signed_int32_list(self):
        number = self.model().number_grid
        for labels in [(0, 0, 0, 0), [], [0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, True],
                       [0, 0, 0, 1.0], [0, 0, 0, 1 << 31], [0, 0, 0, -(1 << 31) - 1]]:
            with self.subTest(labels=labels), self.assertRaises(ValueError): number(labels, 2, 2, 3)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.input = self.root / "input.json"
        self.output = self.root / "output.json"

    def tearDown(self): self.temp.cleanup()

    def run_cli(self, value=None, raw=None, extra=()):
        cli = HERE / "grid.py"
        self.assertTrue(cli.is_file(), "Recovered stdlib CLI is not implemented")
        if raw is not None: self.input.write_bytes(raw)
        elif value is not None: self.input.write_text(json.dumps(value), encoding="utf-8")
        return subprocess.run([sys.executable, "-X", "utf8", "-B", "-I", "-S", str(cli), "--input", str(self.input),
                               "--out", str(self.output), *extra], capture_output=True, encoding="utf-8", errors="strict", timeout=5)

    def rejected(self, **arguments):
        result = self.run_cli(**arguments)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["status"], "failed")
        self.assertFalse(self.output.exists())

    def test_real_cli_writes_complete_output_and_count(self):
        result = self.run_cli(canonical_case())
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        value = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(value, {"schema_version": 1, "kind": "recovered_grid_numbering", "case_id": "small-2", "width": 2,
                                 "height": 2, "node_stride": 3, "nodes": [0, 6, 3, 1, -1, 4, 2, 7, 5], "node_count": 8, "target_rva": "0x98a50"})

    def test_dense_labels_do_not_include_source_stride_padding(self):
        result = self.run_cli(canonical_case(source_stride=10))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(self.output.read_text(encoding="utf-8"))["node_count"], 8)

    def test_existing_output_is_never_overwritten(self):
        self.output.write_text("old-evidence", encoding="utf-8")
        result = self.run_cli(canonical_case())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "old-evidence")

    def test_input_and_output_same_path_never_changes_input(self):
        self.output = self.input
        original = json.dumps(canonical_case()).encode("utf-8")
        result = self.run_cli(raw=original)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.input.read_bytes(), original)

    def test_input_hardlink_is_rejected(self):
        self.input.write_text(json.dumps(canonical_case()), encoding="utf-8")
        os.link(self.input, self.root / "other.json")
        self.rejected()

    def test_input_junction_or_symlink_is_rejected(self):
        actual = self.root / "real"; actual.mkdir()
        source = actual / "input.json"; source.write_text(json.dumps(canonical_case()), encoding="utf-8")
        alias = self.root / "alias"
        if os.name == "nt":
            # Junction creation uses only an owned directory and ordinary cmd builtin.
            child = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(actual)], capture_output=True)
            self.assertEqual(child.returncode, 0)
        else: alias.symlink_to(actual, target_is_directory=True)
        self.input = alias / "input.json"
        self.rejected()

    def test_extra_or_missing_case_field_is_rejected(self):
        for value in [{**canonical_case(), "pid": 123}, {k: v for k, v in canonical_case().items() if k != "id"}]:
            with self.subTest(value=value): self.rejected(value=value)

    def test_bad_ids_source_stride_and_boolean_are_rejected(self):
        for patch in [{"id": ".first"}, {"id": "x" * 65}, {"id": "中文"}, {"source_stride": True},
                      {"source_stride": 1}, {"source_stride": 11}, {"width": True}, {"labels": [0, 0, 0, False]}]:
            with self.subTest(patch=patch): self.rejected(value=canonical_case(**patch))

    def test_duplicate_json_keys_are_rejected(self):
        self.rejected(raw=b'{"id":"old","id":"new","width":2,"height":2,"node_stride":3,"source_stride":2,"labels":[0,0,0,0]}')

    def test_nonfinite_and_invalid_utf8_are_rejected(self):
        for raw in [json.dumps(canonical_case()).replace('[0, 0, 0, 0]', '[NaN,0,0,0]').encode("utf-8"), b'\xff']:
            with self.subTest(raw=raw): self.rejected(raw=raw)

    def test_oversize_input_is_rejected_before_output(self):
        self.rejected(raw=b' ' * 65537)

    def test_repeated_option_is_rejected(self):
        self.rejected(value=canonical_case(), extra=("--input", str(self.input)))

    def test_output_special_alias_component_is_rejected(self):
        self.output = self.root / "output.json:stream"
        self.rejected(value=canonical_case())


if __name__ == "__main__": unittest.main(verbosity=2)
