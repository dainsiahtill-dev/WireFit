"""Fixed state expectations for the bounded label forest contract; no emulation."""
from dataclasses import FrozenInstanceError
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent


class LabelModelTests(unittest.TestCase):
    def model(self):
        source = HERE / 'model.py'
        self.assertTrue(source.is_file(), 'Independent label-state model is not implemented')
        if 'label_state_test_model' not in sys.modules:
            spec = importlib.util.spec_from_file_location('label_state_test_model', source)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module; spec.loader.exec_module(module)
        return sys.modules['label_state_test_model']

    def test_lookup_compresses_only_initial_parent_and_selected_pixel(self):
        m = self.model(); state = m.LabelState(2, 2, (0, 0, 1, 4), (1, 2, 3, -7, -1), 123, 19)
        result = m.lookup(state, 0)
        self.assertEqual(result.representative, 3)
        self.assertEqual(result.state, m.LabelState(2, 2, (3, 0, 1, 4), (3, 2, 3, -7, -1), 123, 19))
        self.assertEqual(state.labels, (0, 0, 1, 4))
        self.assertEqual(state.parents, (1, 2, 3, -7, -1))

    def test_lookup_initial_root_is_strict_noop(self):
        m = self.model(); state = m.LabelState(2, 1, (1, 0), (-2, -2147483648), -14, 255)
        result = m.lookup(state, 0)
        self.assertIs(result.state, state)
        self.assertEqual(result.representative, 1)

    def test_lookup_direct_parent_preserves_every_neighbor(self):
        m = self.model(); state = m.LabelState(3, 1, (0, 0, 2), (1, -3, -11), 5, 0)
        result = m.lookup(state, 1)
        self.assertEqual(result.state.labels, (0, 1, 2))
        self.assertEqual(result.state.parents, (1, -3, -11))
        self.assertEqual((result.state.components, result.state.dirty), (5, 0))

    def test_merge_roots_updates_only_drop_parent_dirty_and_count(self):
        m = self.model(); state = m.LabelState(2, 1, (2, 1), (-9, -2, 1), 17, 255)
        result = m.merge_roots(state, 0, 1)
        self.assertEqual(result, m.LabelState(2, 1, (2, 1), (-9, 0, 1), 16, 1))
        self.assertEqual(state.parents, (-9, -2, 1))

    def test_merge_count_wraps_signed_int32(self):
        m = self.model(); state = m.LabelState(1, 1, (0,), (-1, -1), -2147483648, 0)
        self.assertEqual(m.merge_roots(state, 0, 1).components, 2147483647)

    def test_merge_requires_two_different_existing_roots(self):
        m = self.model(); state = m.LabelState(1, 1, (0,), (-1, -2, 1), 2, 0)
        for keep, drop in [(0, 0), (0, 2), (2, 0), (-1, 0), (0, 3), (True, 1), (0, False)]:
            with self.subTest(pair=(keep, drop)), self.assertRaises(ValueError): m.merge_roots(state, keep, drop)

    def test_normalize_dirty_zero_preserves_chain_and_negative_markers(self):
        m = self.model(); state = m.LabelState(2, 1, (0, 3), (1, 2, -7, -9), -101, 0)
        self.assertIs(m.normalize(state), state)

    def test_normalize_relabels_all_pixels_then_resets_all_parents(self):
        m = self.model(); state = m.LabelState(2, 2, (0, 1, 3, 0), (1, 2, -7, -9, -2147483648), -101, 255)
        self.assertEqual(m.normalize(state), m.LabelState(2, 2, (2, 2, 3, 2), (-1, -1, -1, -1, -1), -101, 0))
        self.assertEqual(state.parents, (1, 2, -7, -9, -2147483648))

    def test_normalize_already_root_pixels_still_resets_unused_parents(self):
        m = self.model(); state = m.LabelState(1, 1, (0,), (-8, 2, -3, -99), 0, 1)
        self.assertEqual(m.normalize(state), m.LabelState(1, 1, (0,), (-1, -1, -1, -1), 0, 0))

    def test_merge_lookup_normalize_composition_has_fixed_expected_state(self):
        m = self.model(); start = m.LabelState(2, 1, (0, 2), (-1, -7, 1), 3, 0)
        merged = m.merge_roots(start, 0, 1)
        looked = m.lookup(merged, 1)
        self.assertEqual(looked.representative, 0)
        self.assertEqual(looked.state, m.LabelState(2, 1, (0, 0), (-1, 0, 0), 2, 1))
        normalized = m.normalize(looked.state)
        self.assertEqual(normalized, m.LabelState(2, 1, (0, 0), (-1, -1, -1), 2, 0))
        self.assertIs(m.normalize(normalized), normalized)

    def test_maximum_256_parent_chain_and_16_square_are_valid(self):
        m = self.model(); parents = tuple(range(1, 256)) + (-1,)
        state = m.LabelState(16, 16, (0,) * 256, parents, 1, 0)
        result = m.lookup(state, 255)
        self.assertEqual(result.representative, 255)
        self.assertEqual(result.state.parents[0], 255)
        self.assertEqual(result.state.parents[1], 2)
        self.assertEqual(result.state.labels[:-1], (0,) * 255)

    def test_self_and_unreferenced_cycles_are_rejected(self):
        m = self.model()
        for parents in [(0,), (1, 0), (-1, 2, 1), (1, 2, 0)]:
            with self.subTest(parents=parents), self.assertRaises(ValueError): m.LabelState(1, 1, (0,), parents, 1, 0)

    def test_labels_and_parent_indices_must_be_in_bounds(self):
        m = self.model()
        for labels, parents in [((-1,), (-1,)), ((1,), (-1,)), ((0,), (1,)), ((0,), (-1, 2)), ((0,), (-2147483649,))]:
            with self.subTest(labels=labels, parents=parents), self.assertRaises(ValueError): m.LabelState(1, 1, labels, parents, 1, 0)

    def test_dimensions_label_shape_and_parent_capacity_are_bounded(self):
        m = self.model()
        for args in [(0,1,(0,),(-1,),1,0),(17,1,(0,)*17,(-1,),1,0),(1,0,(0,),(-1,),1,0),
                     (1,17,(0,)*17,(-1,),1,0),(2,2,(0,),(-1,),1,0),(1,1,(0,),(),1,0),
                     (1,1,(0,),(-1,)*257,1,0)]:
            with self.subTest(args=args[:2]), self.assertRaises(ValueError): m.LabelState(*args)

    def test_all_scalar_and_element_bool_inputs_are_rejected(self):
        m = self.model()
        invalid = [(True,1,(0,),(-1,),1,0),(1,False,(0,),(-1,),1,0),(1,1,(True,),(-1,),1,0),
                   (1,1,(0,),(False,),1,0),(1,1,(0,),(-1,),True,0),(1,1,(0,),(-1,),1,False)]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError): m.LabelState(*args)

    def test_tuple_storage_and_signed_count_unsigned_dirty_are_strict(self):
        m = self.model()
        for args in [(1,1,[0],(-1,),1,0),(1,1,(0,),[-1],1,0),(1,1,(0,),(-1,),2147483648,0),
                     (1,1,(0,),(-1,),-2147483649,0),(1,1,(0,),(-1,),1,-1),(1,1,(0,),(-1,),1,256),
                     (1,1,(0,),(-1,),1.0,0),(1,1,(0.0,),(-1,),1,0)]:
            with self.subTest(args=args), self.assertRaises(ValueError): m.LabelState(*args)

    def test_lookup_pixel_index_is_strict_and_bounded(self):
        m = self.model(); state = m.LabelState(1, 1, (0,), (-1,), 1, 0)
        for index in (-1, 1, True, 0.0):
            with self.subTest(index=index), self.assertRaises(ValueError): m.lookup(state, index)

    def test_state_and_lookup_result_are_frozen(self):
        m = self.model(); state = m.LabelState(1, 1, (0,), (-1,), 1, 0)
        result = m.lookup(state, 0)
        with self.assertRaises(FrozenInstanceError): state.dirty = 1
        with self.assertRaises(FrozenInstanceError): result.representative = 5
        for fn, args in [(m.lookup,({},0)),(m.merge_roots,({},0,1)),(m.normalize,({},))]:
            with self.assertRaises(ValueError): fn(*args)


if __name__ == '__main__': unittest.main(verbosity=2)
