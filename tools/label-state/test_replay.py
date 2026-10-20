"""Pure host boundaries and real safe Python CLI failures; no Unicorn import."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent


class LabelReplayTests(unittest.TestCase):
    def module(self):
        source = HERE / 'replay.py'
        self.assertTrue(source.is_file(), 'Bounded label-state replay is not implemented')
        if 'label_replay_test' not in sys.modules:
            spec = importlib.util.spec_from_file_location('label_replay_test', source)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module; spec.loader.exec_module(module)
        return sys.modules['label_replay_test']

    def test_bootstrap_is_pinned_and_does_not_import_unicorn(self):
        m = self.module(); helper, metadata = m.bootstrap()
        self.assertEqual(metadata['sha256'], '440ccbd82f3056bfe6b08fb16b63be860bea1f66d53f4c6ec68b995b53b15629')
        self.assertTrue(callable(helper.stage_unicorn))
        self.assertFalse(any(name == 'unicorn' or name.startswith('unicorn.') for name in sys.modules))

    def test_bootstrap_wrong_bytes_are_rejected_before_compile(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'bootstrap identity'):
            m.compile_bootstrap(b'raise AssertionError("must not execute")')

    def test_three_bodies_have_exact184bytes_and77instructions(self):
        m = self.module()
        self.assertEqual(sum(len(row[1]) for body in m.BODIES.values() for row in body['rows']), 184)
        self.assertEqual(sum(len(body['rows']) for body in m.BODIES.values()), 77)
        self.assertEqual(m.BODIES['lookup']['entry'], 0x47e8e0)
        self.assertEqual(m.BODIES['merge_roots']['entry'], 0x47e1b0)
        self.assertEqual(m.BODIES['normalize']['entry'], 0x47fcb0)
        for body in m.BODIES.values():
            self.assertEqual(hashlib.sha256(b''.join(data for _,data in body['rows'])).hexdigest(), body['sha256'])

    def test_normalize_gap_is_cc_not_concatenated_body_bytes(self):
        m = self.module(); pages = m.code_pages()
        page = pages[0x47f000]
        self.assertEqual(page[0xcbb:0xcbd], bytes.fromhex('eb03'))
        self.assertEqual(page[0xcbd:0xcc0], b'\xcc' * 3)
        self.assertEqual(page[0xcc0:0xcc3], bytes.fromhex('8b4108'))
        for address in (0x47fcbd,0x47fcbe,0x47fcbf):
            with self.assertRaises(ValueError): m.check_instruction('normalize',address,1,0)

    def test_image_mapping_rejects_wrong_full_image_pin(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'image identity'): m.verify_image(b'MZ'+bytes(4096))

    def test_real_fixed_pe_mapping_checks_all77_instruction_bytes(self):
        m = self.module(); helper,_ = m.bootstrap()
        source = HERE.parents[1] / 'exports' / 'vmde-20261020' / 'unpacked_vmde.exe'
        rows = m.verify_image(helper.stable_read(source,16*1024*1024))
        self.assertEqual(len(rows),77)
        self.assertTrue(all(row['matches'] for row in rows))
        self.assertTrue(any(row['rva'] != row['raw_file_offset'] for row in rows))

    def test_cases_are_constructed_only_after_exact_model_freeze(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'model'): m.build_scenarios('0'*64)
        scenarios = m.build_scenarios(m.MODEL_SHA256)
        self.assertLessEqual(len(scenarios),64)
        calls = [operation for scenario in scenarios for operation in scenario['operations']]
        self.assertLessEqual(len(calls),96)
        self.assertGreaterEqual(len(scenarios),8)
        self.assertEqual({row['method'] for row in calls},{'lookup','merge_roots','normalize'})
        self.assertTrue(any(len(row['state']['parents'])==256 for row in scenarios))
        self.assertTrue(any(row['state']['components']==-2147483648 for row in scenarios))
        self.assertTrue(any(row['state']['dirty']==255 for row in scenarios))

    def test_pc_method_and_step_boundaries_are_enforced(self):
        m = self.module()
        m.check_instruction('lookup',0x47e8e0,2,0)
        for method,pc,size,steps in [('lookup',0x47e1b0,3,0),('lookup',0x47e8e1,1,0),
                                    ('lookup',0x47e8e0,3,0),('lookup',0x47e8e0,2,65536)]:
            with self.subTest(pc=pc), self.assertRaises(ValueError): m.check_instruction(method,pc,size,steps)

    def test_allowed_writes_are_bound_to_actual_instruction_and_saved_slot(self):
        m = self.module(); layout = {'context':0x20001100,'labels':0x30001ff0,'parents':0x40001ff0,'stack':0x50001f00}
        state = {'width':2,'height':1,'labels':[0,1],'parents':[1,-1],'components':2,'dirty':0}
        m.check_write('lookup',0x47e909,layout['parents'],4,layout,state,[0],0)
        m.check_write('lookup',0x47e90f,layout['labels'],4,layout,state,[0],0)
        m.check_write('lookup',0x47e8e2,layout['stack']-4,4,layout,state,[0],0)
        for pc,address,size in [(0x47e909,layout['parents']+4,4),(0x47e90f,layout['labels']+4,4),
                                (0x47e8e2,layout['stack']-8,4),(0x47e909,layout['context'],4)]:
            with self.subTest(pc=pc,address=address), self.assertRaises(ValueError): m.check_write('lookup',pc,address,size,layout,state,[0],0)

    def test_merge_and_normalize_write_bounds_do_not_admit_unknown_context_bytes(self):
        m = self.module(); layout = {'context':0x20001100,'labels':0x30001ff0,'parents':0x40001ff0,'stack':0x50001f00}
        state = {'width':2,'height':1,'labels':[0,1],'parents':[-1,-1],'components':2,'dirty':255}
        m.check_write('merge_roots',0x47e1bc,layout['context']+24,1,layout,state,[0,1],0)
        m.check_write('merge_roots',0x47e1c0,layout['parents']+4,4,layout,state,[0,1],0)
        m.check_write('normalize',0x47fd06,layout['parents']+4,4,layout,state,[],0)
        for pc,address,size in [(0x47e1bc,layout['context']+25,1),(0x47e1c0,layout['parents'],4),
                                (0x47fd06,layout['parents']+8,4),(0x47fcee,layout['labels']+1,4)]:
            method = 'merge_roots' if pc < 0x47f000 else 'normalize'
            with self.subTest(pc=pc), self.assertRaises(ValueError): m.check_write(method,pc,address,size,layout,state,[0,1] if method=='merge_roots' else [],0)

    def test_negative_state_and_lookup_return_are_independent_checks(self):
        m = self.module(); state = {'width':1,'height':1,'labels':[0],'parents':[-1],'components':1,'dirty':0}
        self.assertTrue(m.compare_observation(state,state,'lookup',0,0)['matched'])
        self.assertFalse(m.compare_observation(state,state,'lookup',1,0)['matched'])
        mutant = dict(state, dirty=1)
        self.assertFalse(m.compare_observation(mutant,state,'normalize',123,None)['matched'])
        self.assertTrue(m.compare_observation(state,state,'normalize',123,None)['matched'])

    def test_cpu_input_is_bound_to_declared_scenario_not_rebased_to_observed_state(self):
        m = self.module()
        self.assertTrue(hasattr(m,'check_input'), 'CPU input binding is not implemented')
        state={'width':1,'height':1,'labels':[0],'parents':[-7,-3],'components':12,'dirty':0}
        m.check_input(dict(state),state)
        for changed in [dict(state,dirty=1),dict(state,components=11),dict(state,parents=[-7,-1]),dict(state,labels=[1])]:
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError,'CPU input'):
                m.check_input(changed,state)

    def invoke(self,*args):
        result = subprocess.run([sys.executable,'-X','utf8','-B','-I','-S',str(HERE/'replay.py'),*args],capture_output=True,timeout=10)
        return result,json.loads(result.stdout.decode('utf-8',errors='strict'))

    def test_real_cli_bad_image_does_not_create_output_or_import_unicorn(self):
        self.module()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); image=root/'bad'; image.write_bytes(b'not the fixed image'); out=root/'out'
            child,value=self.invoke('--module-path',str(root),'--image',str(image),'--out',str(out))
            self.assertEqual(child.returncode,1); self.assertEqual(value['status'],'failed')
            self.assertEqual(value['rows'],[]); self.assertFalse(out.exists()); self.assertEqual(child.stderr,b'')

    def test_real_cli_existing_output_and_duplicate_arguments_are_rejected(self):
        self.module()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); out=root/'out'; out.mkdir(); (out/'sentinel').write_bytes(b'old')
            child,value=self.invoke('--module-path',str(root),'--image','unused','--out',str(out))
            self.assertEqual(child.returncode,1); self.assertEqual((out/'sentinel').read_bytes(),b'old')
            self.assertIn('already exists',value['error']['message'])
        child,value=self.invoke('--module-path','a','--module-path','b','--image','x','--out','y')
        self.assertEqual(child.returncode,1); self.assertIn('Repeated',value['error']['message'])


if __name__ == '__main__': unittest.main(verbosity=2)
