"""Pure protocol, filesystem and fake-owned-process tests; never executes a PE."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kernel_worker_tested', HERE / 'worker.py')
W = importlib.util.module_from_spec(spec)
exec(compile((HERE / 'worker.py').read_text(encoding='utf-8'), str(HERE / 'worker.py'), 'exec'), W.__dict__)
ROOT = HERE.parents[1]
CORPUS = ROOT / 'artifacts/research/vmde/native-kernel/edges8.json'


def result():
    return dict(schema_version=1, status='failed', frida_version='17.2.17', pid=None,
                events=[], snapshots=[], omitted_events=0, omitted_events_complete=False,
                hook_states=dict(initial=[], current=[], final=[]), hook_states_complete=False,
                cleanup=dict(owned_pid_terminated=False, session_detached=False,
                             windows_job_assigned=False, windows_job_closed=False), error=None)


def case():
    return dict(id='test-1', width=2, height=2, node_stride=3, source_stride=2, labels=[0, 0, 0, 1])


def native_row(c, main, output=None):
    output = output or list(range(c['node_stride'] * (c['height'] + 1)))
    raw = struct.pack('<' + 'i' * len(output), *output)
    sizes = dict(context=156, header=12, source=c['source_stride'] * c['height'] * 4, nodes=len(raw))
    buffers = [dict(name=name, allocation=hex(0x200000 + i * 0x10000), data=hex(0x202000 + i * 0x10000 - size),
                    size_bytes=size, data_page=hex(0x201000 + i * 0x10000), page_size=4096,
                    protection='rw-' if name == 'nodes' else 'r--') for i, (name, size) in enumerate(sizes.items())]
    by = {b['name']: b for b in buffers}
    ctx = bytearray(b'\xa5' * 156)
    for offset, v in ((0, int(by['nodes']['data'], 16)), (4, c['node_stride']), (8, c['height'] + 1),
                      (12, int(by['header']['data'], 16)), (0x94, c['width']), (0x98, c['height'])):
        struct.pack_into('<I', ctx, offset, v)
    src = bytearray(b'\xa5' * sizes['source'])
    for i, label in enumerate(c['labels']):
        struct.pack_into('<i', src, (i // c['width'] * c['source_stride'] + i % c['width']) * 4, label)
    data = dict(context=bytes(ctx), header=struct.pack('<III', int(by['source']['data'], 16), c['source_stride'], c['height']),
                source=bytes(src), nodes=b'\xa5' * sizes['nodes'])
    before = {n: W.digest(b'\xa5' * (4096 - sizes[n]) + d) for n, d in data.items()}
    after = {**before, 'nodes': W.digest(b'\xa5' * (4096 - sizes['nodes']) + raw)}
    names = ['eflags_before', 'esp_before', 'esp_after', 'ebx_before', 'esi_before', 'edi_before', 'ebp_before',
             'ebx_after', 'esi_after', 'edi_after', 'ebp_after', 'eflags_after', 'eax_incidental']
    regs = dict(zip(names, [0x202, 0x180000, 0x180000, 1, 2, 3, 4, 1, 2, 3, 4, 0x202, 0]))
    identity = dict(main_base=main['base'], entry=hex(int(main['base'], 16) + 0x1030),
                    body_sha256=W.PROFILES['positive-control']['body_sha256'])
    return dict(id=c['id'], status='completed', output=output, evidence=dict(
        before=identity, after=identity.copy(), invocation_started=True, invocation_returned=True, capture_errors=[],
        register_observation='captured_by_wrapper', registers=regs, raw_register_state_hex=struct.pack('<13I', *regs.values()).hex(),
        checks={k: True for k in W.CHECKS}, buffers=buffers, buffer_before_sha256=before, buffer_after_sha256=after,
        output_hex=raw.hex(), output_sha256=W.digest(raw)))


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.main = dict(base='0x400000', size=0x20000, path=str(ROOT / 'fake-staged.exe'))

    def test_real_windows_retained_read_allows_different_stat_fstat_ctime(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'data.json'
            file.write_text('ordinary UTF-8', encoding='utf-8')
            self.assertEqual(W.stable_bytes(file, 1024), b'ordinary UTF-8')

    def test_cross_api_ctime_difference_is_not_input_change(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'a.json'; file.write_bytes(b'a')
            original = os.fstat
            def fstat(fd):
                value = original(fd)
                from types import SimpleNamespace
                fields = {k: getattr(value, k) for k in dir(value) if k.startswith('st_')}
                fields['st_ctime_ns'] += 123456789
                return SimpleNamespace(**fields)
            with patch.object(os, 'fstat', fstat):
                self.assertEqual(W.stable_bytes(file, 1024), b'a')

    def test_hardlinks_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'a'; file.write_bytes(b'a'); os.link(file, Path(d) / 'b')
            with self.assertRaises(W.KernelFailure): W.stable_bytes(file, 1024)

    def test_ads_and_junction_rejected(self):
        if os.name != 'nt': self.skipTest('Windows path semantics')
        with tempfile.TemporaryDirectory() as d:
            file = Path(d) / 'a'; file.write_bytes(b'a')
            with self.assertRaises(W.KernelFailure): W.stable_bytes(str(file) + ':stream', 1024)
            with patch.object(Path, 'is_junction', lambda p: p == file.parent):
                with self.assertRaises(W.KernelFailure): W.stable_bytes(file, 1024)

    def test_case_id_matches_corpus_intersection(self):
        for bad in ['.leading', 'x' * 65]:
            with self.subTest(bad=bad), self.assertRaises(W.KernelFailure): W.validate_case({**case(), 'id': bad})

    def test_corpus_rejects_boolean_schema_and_relative_candidate(self):
        value = json.loads(CORPUS.read_text(encoding='utf-8'))
        for change in [dict(schema_version=True), dict(candidate={**value['candidate'], 'path': 'relative.py'})]:
            with self.subTest(change=change), self.assertRaises(W.KernelFailure): W.validate_corpus({**value, **change})

    def test_completed_row_independent_bytes_and_invariants(self):
        self.assertEqual(W.validate_row(native_row(case(), self.main), case(), 'positive-control', self.main)['status'], 'completed')

    def test_completed_with_error_rejected(self):
        row = native_row(case(), self.main); row['error'] = dict(code='X', message='original failure')
        with self.assertRaises(W.KernelFailure): W.validate_row(row, case(), 'positive-control', self.main)

    def test_independent_component_mutations_are_rejected(self):
        mutations = [lambda r: r['evidence']['registers'].update(esp_after=0x170000),
                     lambda r: r['evidence'].update(output_hex='00' * 36),
                     lambda r: r['evidence']['buffer_before_sha256'].update(source='0' * 64),
                     lambda r: r['evidence']['buffer_after_sha256'].update(nodes='0' * 64),
                     lambda r: r['evidence']['buffers'][1].update(allocation='0x200000'),
                     lambda r: r['evidence']['checks'].update(nodes_guards=False),
                     lambda r: r['evidence'].update(invocation_returned=False),
                     lambda r: r['evidence']['before'].update(body_sha256='0' * 64)]
        for index, mutate in enumerate(mutations):
            row = native_row(case(), self.main); mutate(row)
            with self.subTest(index=index), self.assertRaises(W.KernelFailure): W.validate_row(row, case(), 'positive-control', self.main)

    def test_failed_row_retains_unknown_registers_and_actual_output(self):
        row = dict(id=case()['id'], status='failed', output=[1] * 9, error=dict(code='CALL_ERROR', message='native threw'),
                   evidence=dict(invocation_started=True, invocation_returned=False, registers=None, raw_register_state_hex='a5' * 52))
        self.assertIs(W.validate_row(row, case(), 'positive-control', self.main), row)

    def test_positive_gate_rejects_status_only_fabrication(self):
        control = dict(kind='native_inprocess_kernel', profile='positive-control', status='completed', is_checkpoint=False,
                       source_sha256=W.PROFILES['positive-control']['source_sha256'], source_unchanged=True, error=None,
                       cleanup=dict(owned_pid_terminated=True, session_detached=True, windows_job_assigned=True, windows_job_closed=True),
                       identities=dict(worker=dict(sha256='a' * 64), agent=dict(sha256='b' * 64)),
                       setup=dict(profile='positive-control', arch='ia32', pointer_size=4, wrapper_hex=W.WRAPPER_HEX,
                                  wrapper_sha256=W.digest(bytes.fromhex(W.WRAPPER_HEX)), abi_probe=dict(context='0x10000', observed_context='0x10000', tag=0x8f31d2a5, result=0xd526114c, expected=0xd526114c)),
                       rows=[dict(status='completed')] * 8)
        with self.assertRaises(W.KernelFailure): W.validate_control(W.encoded(control), 'a' * 64, 'b' * 64)

    def control_receipt(self):
        corpus_bytes = CORPUS.read_bytes(); corpus = json.loads(corpus_bytes)
        target = ROOT / 'artifacts/native/kernel-control-build-v2-20261020/wirefit-kernel-control.exe'
        raw = target.read_bytes(); pe = struct.unpack_from('<I', raw, 0x3c)[0]
        opt = pe + 24; size = struct.unpack_from('<I', raw, opt + 56)[0]
        count, optional_size = struct.unpack_from('<H', raw, pe + 6)[0], struct.unpack_from('<H', raw, pe + 20)[0]
        body = None
        for i in range(count):
            section = opt + optional_size + i * 40
            virtual, rva, raw_size, offset = struct.unpack_from('<IIII', raw, section + 8)
            if rva <= 0x1030 and 0x1030 + 64 <= rva + raw_size:
                body = raw[offset + 0x1030 - rva:offset + 0x1030 - rva + 64]
        self.assertIsNotNone(body)
        main = dict(base='0x400000', size=size, path=str(target))
        identity = dict(pid=111, arch='ia32', pointer_size=4, main=main, entry='0x401030', body_size_bytes=64,
                        body_hex=body.hex(), body_sha256=W.digest(body), ready=True)
        namespace = {}; candidate = Path(corpus['candidate']['path']).read_text(encoding='utf-8')
        exec(compile(candidate, corpus['candidate']['path'], 'exec'), namespace)
        rows = [native_row(c, main, namespace['recover_grid'](c['labels'], c['width'], c['height'], c['node_stride'])) for c in corpus['cases']]
        setup = FakeRuntime(dict(target=str(target)), corpus).setup({}); setup['main'] = main
        return dict(schema_version=1, kind='native_inprocess_kernel', profile='positive-control', status='completed',
                    is_checkpoint=False, source_sha256=W.PROFILES['positive-control']['source_sha256'], source_unchanged=True,
                    inputs_unchanged=True, error=None, in_flight_id=None,
                    cleanup=dict(owned_pid_terminated=True, session_detached=True, windows_job_assigned=True, windows_job_closed=True),
                    identities=dict(worker=dict(sha256='a' * 64), agent=dict(sha256='b' * 64)), setup=setup,
                    corpus_input=corpus, corpus=dict(path=str(CORPUS), size_bytes=len(corpus_bytes), sha256=W.digest(corpus_bytes), cases_sha256=W.EDGES_HASH, case_count=8),
                    identity_initial=identity, identity_final=copy.deepcopy(identity), rows=rows,
                    finish=dict(completed_calls=8, halted=False))

    def test_positive_gate_accepts_complete_compiled_body_and_eight_byte_checked_rows(self):
        receipt = self.control_receipt()
        self.assertEqual(len(W.validate_control(W.encoded(receipt), 'a' * 64, 'b' * 64)['rows']), 8)

    def test_positive_gate_rejects_each_missing_proof(self):
        original = self.control_receipt()
        mutations = [lambda v: v.pop('identity_initial'), lambda v: v.pop('identity_final'),
                     lambda v: v.pop('corpus_input'), lambda v: v['finish'].update(completed_calls=7),
                     lambda v: v['identity_final'].update(pid=112), lambda v: v['identity_final']['main'].update(base='0x500000'),
                     lambda v: v['setup']['abi_probe'].update(observed_context='0x20000'),
                     lambda v: v['rows'][0]['evidence']['buffer_after_sha256'].update(nodes='0' * 64),
                     lambda v: v['rows'][0].update(output=[0] * len(v['rows'][0]['output'])),
                     lambda v: v['corpus_input']['cases'][0].update(id='different'),
                     lambda v: v['cleanup'].update(windows_job_closed=False)]
        for index, mutate in enumerate(mutations):
            receipt = copy.deepcopy(original); mutate(receipt)
            with self.subTest(index=index), self.assertRaises((W.KernelFailure, KeyError, TypeError)):
                W.validate_control(W.encoded(receipt), 'a' * 64, 'b' * 64)


class Cancellable:
    def __init__(self): self.cancelled = threading.Event()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def cancel(self): self.cancelled.set()
    def raise_if_cancelled(self):
        if self.cancelled.is_set(): raise RuntimeError('Python RPC wait cancelled')


class FakeRuntime:
    """The simulated native call ignores RPC cancellation until Job termination."""
    Cancellable = Cancellable
    def __init__(self, config, corpus, mode='success'):
        self.config, self.corpus, self.mode = config, corpus, mode
        self.closed, self.order, self.calls = threading.Event(), [], 0
        self.kills = []
        self.handlers = {}
        self.main = dict(base='0x400000', size=0x20000, path=config['target'])
        self.is_detached = False
        self.exports_sync = self
        self.assigned = False
        self.process_handle = None
    def get_local_device(self): return self
    def spawn(self, args, **kw): self.order.append('spawn'); return 12345
    def assign(self, pid):
        self.order.append('assign')
        if self.mode in ('assign-error', 'kill-blocked'): raise W.KernelFailure('ASSIGN_FAILED', 'OpenProcess failed')
        self.assigned = True
    def close(self):
        self.order.append('close_job'); self.closed.set()
        if self.mode in ('close-error', 'rpc-and-close-error'): raise RuntimeError('Job close failed')
        return dict(owned_pid_terminated=self.assigned, windows_job_assigned=self.assigned, windows_job_closed=True, errors=[])
    def kill(self, pid, cancellable=None):
        self.kills.append(pid)
        if self.mode == 'kill-blocked':
            if cancellable is None or not cancellable.cancelled.wait(4): raise AssertionError('Unbounded fallback')
            raise RuntimeError('Owned spawn kill wait cancelled')
    def attach(self, pid): self.order.append('attach'); return self
    def on(self, name, handler): self.handlers[name] = handler
    def create_script(self, *args, **kw): return self
    def set_log_handler(self, *args): pass
    def load(self): pass
    def setup(self, value):
        expected = 0x8f31d2a5 ^ 0x5a17c3e9
        return dict(profile='positive-control', arch='ia32', pointer_size=4, main=self.main,
                    wrapper_hex=W.WRAPPER_HEX, wrapper_sha256=W.digest(bytes.fromhex(W.WRAPPER_HEX)),
                    abi_probe=dict(context='0x10000', observed_context='0x10000', tag=0x8f31d2a5, result=expected, expected=expected))
    def resume(self, pid): self.order.append('resume')
    def identity(self):
        return dict(pid=12345, arch='ia32', pointer_size=4, main=self.main, entry='0x401030', body_size_bytes=64,
                    body_hex='63' * 64, body_sha256=W.digest(b'c' * 64), ready=True)
    def run(self, c):
        self.calls += 1
        if self.mode == 'blocked':
            if not self.closed.wait(2): raise AssertionError('Native call did not end on owned Job close')
            raise RuntimeError('Native target was terminated')
        if self.mode == 'agent-first':
            self.handlers['message'](dict(type='error', description='First agent failure'), None)
            self.closed.wait(2)
            raise RuntimeError('Later target termination')
        if self.mode in ('rpc-error', 'rpc-and-close-error') and self.calls == 2: raise W.KernelFailure('ORIGINAL_RPC', 'Second native call failed')
        row = native_row(c, self.main)
        if self.mode == 'invalid-row': row['evidence']['buffer_before_sha256']['source'] = '0' * 64
        if self.mode == 'native-failure':
            row['status'] = 'failed'; row['error'] = dict(code='ORIGINAL_NATIVE', message='Actual native exception')
            row['evidence']['registers'] = None
        return row
    def finish(self): return dict(completed_calls=self.calls, halted=False)
    def detach(self, cancellable=None): self.order.append('detach'); self.is_detached = True


class LifecycleTests(unittest.TestCase):
    def experiment(self, mode='success', duration=2000, count=8, corpus_name='edges8.json'):
        corpus = json.loads(CORPUS.with_name(corpus_name).read_text(encoding='utf-8')); corpus['cases'] = corpus['cases'][:count]
        config = dict(target=str(Path.cwd() / 'staged.exe'), duration_ms=duration, breakpoints_rva=[],
                      ranges=[dict(rva='0x1030', size_bytes=64)], api_hooks=[], max_events=512)
        out = result(); support, _ = W.load_support(); checkpoint = support.Checkpoint(out)
        receipt = W.NativeReceipt(out, 'positive-control', corpus, {}, {})
        runtime = FakeRuntime(config, corpus, mode)
        with patch.dict(W.PROFILES['positive-control'], body_sha256=W.digest(b'c' * 64)):
            W.run_experiment(config, corpus, 'positive-control', runtime, support, out, 'not executed', checkpoint, receipt, job_factory=lambda: runtime)
        receipt.flush(terminal=True)
        return out, receipt, runtime

    def in_temp(self, callback):
        old = Path.cwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try: return callback()
            finally: os.chdir(old)

    def test_success_records_actual_rows_then_closes_job_before_detach(self):
        def check():
            out, receipt, rt = self.experiment()
            self.assertEqual(out['status'], 'completed', out['error'])
            self.assertEqual(receipt.counts(), dict(completed=8, failed=0, unattempted=0))
            self.assertLess(rt.order.index('assign'), rt.order.index('resume'))
            self.assertLess(rt.order.index('close_job'), rt.order.index('detach'))
            self.assertEqual([s['phase'] for s in out['snapshots']], ['initial', 'final'])
            rows = [r for e in out['events'] if e['type'] == 'native_kernel_cases' for r in e['rows']]
            self.assertEqual(rows[0]['output'], receipt.doc['rows'][0]['output'])
            self.assertNotIn('evidence', rows[0])
            self.assertEqual(len(Path('native-calls.jsonl').read_text(encoding='utf-8').splitlines()), 16)
        self.in_temp(check)

    def test_blocked_native_call_ends_from_job_not_rpc_wait(self):
        def check():
            begin = time.monotonic(); out, receipt, rt = self.experiment('blocked', duration=50)
            self.assertLess(time.monotonic() - begin, 1)
            self.assertEqual(out['error']['code'], 'TIMEOUT')
            self.assertTrue(rt.closed.is_set())
            self.assertEqual(receipt.counts(), dict(completed=0, failed=1, unattempted=7))
            self.assertLess(rt.order.index('close_job'), rt.order.index('detach'))
        self.in_temp(check)

    def test_owned_suspended_spawn_fallback_on_no_handle_assignment_failure(self):
        def check():
            out, receipt, rt = self.experiment('assign-error')
            self.assertEqual(out['error']['code'], 'ASSIGN_FAILED')
            self.assertEqual(rt.kills, [12345])
            self.assertNotIn('resume', rt.order)
            self.assertFalse(out['cleanup']['owned_pid_terminated'])
            self.assertEqual(receipt.counts()['unattempted'], 8)
        self.in_temp(check)

    def test_fallback_kill_has_independent_bounded_cancellable(self):
        def check():
            begin = time.monotonic(); out, _, rt = self.experiment('kill-blocked')
            self.assertLess(time.monotonic() - begin, 3.7)
            self.assertEqual(out['error']['code'], 'ASSIGN_FAILED')
            self.assertEqual(rt.kills, [12345])
            self.assertTrue(out['cleanup']['errors'])
        self.in_temp(check)

    def test_close_job_exception_does_not_skip_detach_or_erase_first_error(self):
        def check():
            out, _, rt = self.experiment('close-error')
            self.assertIn('detach', rt.order)
            self.assertEqual(out['status'], 'failed')
            self.assertEqual(out['error']['code'], 'CLEANUP_FAILED')
        self.in_temp(check)

    def test_returned_invalid_proof_is_failed_and_original_raw_return_preserved(self):
        def check():
            out, receipt, rt = self.experiment('invalid-row')
            self.assertEqual(out['status'], 'failed')
            self.assertEqual(rt.calls, 1)
            row = receipt.doc['rows'][0]
            self.assertEqual(row['status'], 'failed')
            self.assertEqual(row['evidence']['agent_return']['status'], 'completed')
            self.assertEqual(receipt.counts()['unattempted'], 7)
        self.in_temp(check)

    def test_native_failure_keeps_actual_output_and_remaining_denominator(self):
        def check():
            out, receipt, rt = self.experiment('native-failure')
            self.assertEqual(out['error']['code'], 'ORIGINAL_NATIVE')
            self.assertEqual(rt.calls, 1)
            self.assertIn('output', receipt.doc['rows'][0])
            self.assertIsNone(receipt.doc['rows'][0]['evidence']['registers'])
            self.assertEqual(receipt.counts(), dict(completed=0, failed=1, unattempted=7))
        self.in_temp(check)

    def test_rpc_failure_preserves_completed_prefix_and_original_error(self):
        def check():
            out, receipt, rt = self.experiment('rpc-error')
            self.assertEqual(out['error']['code'], 'ORIGINAL_RPC')
            self.assertEqual(receipt.counts(), dict(completed=1, failed=1, unattempted=6))
            self.assertIn('output', receipt.doc['rows'][0])
            self.assertTrue(out['cleanup']['owned_pid_terminated'])
        self.in_temp(check)

    def test_timeout_at_completion_boundary_cannot_become_completed(self):
        def check():
            support, _ = W.load_support()
            original, timers = threading.Timer, []
            hooks = support.Collector.hook_states
            def timer(interval, callback, *args, **kwargs):
                selected = original(interval, callback, *args, **kwargs)
                if callback.__name__ == 'timeout': timers.append(selected)
                return selected
            def hook_states(collector, states, phase):
                hooks(collector, states, phase)
                if phase == 'final': timers[0].function()
            with patch.object(W, 'load_support', return_value=(support, None)), patch.object(threading, 'Timer', timer), patch.object(support.Collector, 'hook_states', hook_states):
                out, _, _ = self.experiment(duration=2000)
            self.assertEqual(out['status'], 'failed')
            self.assertEqual(out['error']['code'], 'TIMEOUT')
        self.in_temp(check)

    def test_cleanup_exception_preserves_earlier_rpc_error_and_completed_prefix(self):
        def check():
            out, receipt, rt = self.experiment('rpc-and-close-error')
            self.assertEqual(out['error']['code'], 'ORIGINAL_RPC')
            self.assertEqual(receipt.counts(), dict(completed=1, failed=1, unattempted=6))
            self.assertTrue(out['cleanup']['errors'])
            self.assertIn('detach', rt.order)
        self.in_temp(check)

    def test_earlier_agent_failure_survives_later_deadline(self):
        def check():
            out, _, _ = self.experiment('agent-first', duration=50)
            self.assertEqual(out['status'], 'failed')
            self.assertEqual(out['error']['code'], 'AGENT_ERROR')
            self.assertIn('First agent failure', out['error']['message'])
        self.in_temp(check)

    def test_896_bounded_receipts_and_basic_events_have_no_per_call_full_rewrite(self):
        def check():
            flushes, bytes_written = [], []
            atomic = W.NativeReceipt.atomic
            def counted(receipt, path, temporary, data):
                if path.name == 'native-result.json': flushes.append(len(data))
                bytes_written.append(len(data))
                return atomic(receipt, path, temporary, data)
            begin = time.monotonic()
            with patch.object(W.NativeReceipt, 'atomic', counted):
                out, receipt, _ = self.experiment(duration=60000, count=896, corpus_name='legacy896.json')
            elapsed = time.monotonic() - begin
            self.assertEqual(out['status'], 'completed', out['error'])
            self.assertEqual(receipt.counts()['completed'], 896)
            self.assertLessEqual(len(flushes), 64)
            self.assertLess(Path('native-result.json').stat().st_size, W.MAX_NATIVE)
            self.assertLess(len(W.encoded(out)), 4 * 1024 * 1024)
            self.assertLess(sum(len(W.encoded(e)) for e in out['events']), 3 * 1024 * 1024)
            self.assertEqual(len(Path('native-calls.jsonl').read_text(encoding='utf-8').splitlines()), 1792)
            print(json.dumps(dict(test='fake_896_no_native_execution', elapsed_seconds=round(elapsed, 4),
                                  native_full_writes=len(flushes), atomic_bytes=sum(bytes_written),
                                  native_result_bytes=Path('native-result.json').stat().st_size,
                                  trace_json_bytes=len(W.encoded(out)))), flush=True)
        self.in_temp(check)


if __name__ == '__main__': unittest.main(verbosity=2)
