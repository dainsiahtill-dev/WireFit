"""Synthetic observer boundaries only: no target/Win32 calls."""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import shutil
from contextlib import contextmanager
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
EXE = str(HERE / "synthetic.exe")
DLL = str(HERE / "QtCore4.dll")


@contextmanager
def temporary_fixture():
    folder = Path(tempfile.mkdtemp(prefix="wirefit-export-test-")).absolute()
    try:
        yield str(folder)
    finally:
        root = Path(tempfile.gettempdir()).resolve(strict=True)
        resolved = folder.resolve(strict=True)
        if resolved.parent != root or resolved != folder or not resolved.name.startswith("wirefit-export-test-"):
            raise AssertionError("Refusing recursive cleanup outside the checked owned temporary directory")
        shutil.rmtree(folder)


def request(**changes):
    row = {"schema_version": 1, "pid": 123, "expected_executable": EXE,
           "expected_creation_filetime": "134369128310367119", "source_sha256": "a"*64,
           "expected_module_file": DLL, "module_sha256": "b"*64,
           "symbols": ["??0QSettings@@QAE@PAVQObject@@@Z"],
           "sample_offsets_ms": [0, 25], "timeout_ms": 1000}
    row.update(changes)
    return row


class Clock:
    def __init__(self): self.now = 0.0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


class NativeFailure(Exception):
    def __init__(self, winerror):
        self.winerror = winerror
        self.code = "MODULE_SNAPSHOT_FAILED"
        super().__init__("native snapshot error")


class Modules:
    def __init__(self, rows=None, failures=0):
        self.rows = rows if rows is not None else [
            {"pid": 123, "name": "QtCore4.dll", "path": DLL, "base": 0x67000000, "size_bytes": 0x340000}]
        self.failures, self.closed, self.opens, self.index = failures, [], 0, 0
    def snapshot(self, pid):
        self.opens += 1
        if self.opens <= self.failures: raise NativeFailure(24)
        self.index = 0
        return 77 + self.opens
    def first(self, handle):
        return self.rows[0] if self.rows else None
    def next(self, handle):
        self.index += 1
        return self.rows[self.index] if self.index < len(self.rows) else None
    def close(self, handle): self.closed.append(handle)


class Reader:
    def __init__(self, **changes):
        self.reads, self.queries, self.identities, self.closed = [], [], 0, False
        self.change_identity_at = changes.get("change_identity_at", 0)
        self.exit_at = changes.get("exit_at", 0)
        self.region = {"base_address": 0x67000000, "allocation_base": 0x67000000,
                       "allocation_protect": 0x20, "region_size": 0x340000,
                       "state": 0x1000, "protect": 0x20, "type": 0x1000000,
                       "returned_size": 48}
        self.region.update(changes.get("region", {}))
        self.read_result = changes.get("read_result")
        self.close_error = changes.get("close_error", False)
    def identity(self):
        self.identities += 1
        return {"pid": 123, "executable": EXE, "creation_filetime":
                "134369128310367120" if self.change_identity_at and self.identities >= self.change_identity_at else "134369128310367119",
                "alive": not (self.exit_at and self.identities >= self.exit_at),
                "exit_filetime": "0", "exit_code": 259}
    def query(self, address):
        self.queries.append(address)
        return dict(self.region)
    def read(self, address, length):
        self.reads.append((address, length))
        return self.read_result or {"data": b"A"*length, "transferred_bytes": length,
                                    "success": True, "winerror": 0}
    def close(self):
        self.closed = True
        if self.close_error: raise OSError("close failed")


class Model:
    def __init__(self, clock=None, fail_at=0):
        self.calls, self.clock, self.fail_at = [], clock, fail_at
    def inspect_exports(self, read_rva, query_va, base, size, symbols, **kwargs):
        self.calls.append(base)
        if self.fail_at and len(self.calls) == self.fail_at: raise ValueError("model sample failed")
        row = read_rva(0, 16)
        query = query_va(base+0x1000)
        if self.clock: self.clock.now += .010
        return {"schema_version": 1, "kind": "runtime_exports", "status": "completed",
                "module": {"base": hex(base), "size_bytes": size},
                "requested_symbols": list(symbols), "exports": [],
                "reads": [{"hex": row["data"].hex()}], "queries": [query],
                "errors": [], "atomic": False, "frida_export_type": None}


class ObserverTests(unittest.TestCase):
    @classmethod
    def module(cls):
        source = HERE / "observe.py"
        assert source.is_file(), "Owned RPM observer is not implemented"
        if "runtime_observe_test" not in sys.modules:
            spec = importlib.util.spec_from_file_location("runtime_observe_test", source)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module; spec.loader.exec_module(module)
        return sys.modules["runtime_observe_test"]

    def bound(self, reader=None):
        m = self.module(); memory, regions, _ = m.load_frozen_support()
        clock = Clock()
        bound = m.BoundReader(reader or Reader(), memory, regions, request(),
                              {"base": 0x67000000, "size_bytes": 0x340000},
                              clock=clock, deadline=1.0)
        return bound

    def collect(self, out, reader=None, modules=None, model=None, config=None):
        m = self.module(); memory, regions, _ = m.load_frozen_support()
        clock = Clock()
        model = model or Model()
        result = m.collect_samples(config or request(), out, reader or Reader(),
                                   modules or Modules(), model, memory, regions,
                                   clock=clock, sleep=clock.sleep)
        return result, model

    def test_strict_request_rejects_bool_unknown_and_bad_schedule(self):
        m = self.module()
        for changes in ({"pid": True}, {"extra": 1}, {"sample_offsets_ms": [25]},
                        {"sample_offsets_ms": [0, 0]}, {"sample_offsets_ms": [0, 8001]},
                        {"sample_offsets_ms": [0, 999], "timeout_ms": 999},
                        {"symbols": ["a", "a"]}, {"symbols": ["a"]*9},
                        {"expected_creation_filetime": 134369128310367119}):
            with self.subTest(changes=changes), self.assertRaises(m.ObserverError):
                m.validate_request(request(**changes))
        self.assertEqual(m.validate_request(request())["pid"], 123)

    def test_json_rejects_duplicate_keys_nan_and_bad_utf8(self):
        m = self.module()
        for data in (b'{"a":1,"a":2}', b'{"x":NaN}', b"\xff", b" "*65537):
            with self.subTest(data=data[:20]), self.assertRaises(m.ObserverError): m.decode_request(data)

    def test_path_rejects_ads_reserved_names_and_alias_components(self):
        m = self.module()
        for value in ("C:\\file:ads", "C:\\x\\NUL.json", "C:\\x\\bad.\\a", "C:\\x\\..\\a"):
            with self.subTest(value=value), self.assertRaises(m.ObserverError): m.strict_path(value)
        with temporary_fixture() as folder:
            root = Path(folder)
            target = root/"target"; target.mkdir()
            alias = root/"alias"
            try: alias.symlink_to(target, target_is_directory=True)
            except OSError: return
            with self.assertRaises(m.ObserverError): m.check_ordinary_path(alias/"new", must_exist=False)

    def test_pinned_support_is_cached_compile_only(self):
        m = self.module(); memory, regions, identities = m.load_frozen_support()
        self.assertEqual([x["sha256"] for x in identities],
                         [m.MEMORY_SHA, m.REGIONS_SHA])
        self.assertTrue(callable(memory.validate_identity))
        self.assertTrue(callable(regions.WindowsRegionReader))
        with self.assertRaises(m.ObserverError):
            m.compile_pinned(b'raise AssertionError("must not execute")', "0"*64, HERE/"bad.py", "bad")

    def test_source_preflight_rejects_wrong_sha_without_open_process(self):
        m = self.module()
        with temporary_fixture() as folder:
            p = Path(folder)/"source"; p.write_bytes(b"source")
            with self.assertRaises(m.ObserverError): m.stable_bytes(p, "0"*64, 1024)
            self.assertEqual(m.stable_bytes(p, hashlib.sha256(b"source").hexdigest(), 1024), b"source")

    def test_native_toolhelp_struct_matches_sdk_without_padding(self):
        m = self.module()
        self.assertEqual([name for name, _ in m.MODULEENTRY32W._fields_],
                         ["dwSize", "th32ModuleID", "th32ProcessID", "GlblcntUsage", "ProccntUsage",
                          "modBaseAddr", "modBaseSize", "hModule", "szModule", "szExePath"])
        if os.name == "nt":
            self.assertEqual(ctypes.sizeof(m.MODULEENTRY32W), 1080 if ctypes.sizeof(ctypes.c_void_p) == 8 else 1064)
            self.assertEqual(m.MODULEENTRY32W.modBaseAddr.offset, 24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 20)

    def test_toolhelp_bad_length_retry_is_bounded_and_closes_handle(self):
        m = self.module(); clock = Clock(); api = Modules(failures=2)
        inventory = m.snapshot_modules(api, 123, 1.0, clock=clock, sleep=clock.sleep)
        self.assertTrue(inventory["complete"]); self.assertEqual(api.opens, 3)
        self.assertEqual(api.closed, [80])
        bad = Modules(failures=10)
        self.assertFalse(m.snapshot_modules(bad, 123, 1.0, clock=clock, sleep=clock.sleep)["complete"])
        self.assertEqual(bad.opens, 3)

    def test_module_absence_requires_complete_inventory_and_duplicate_is_unknown(self):
        m = self.module()
        absent = m.resolve_module({"complete": True, "rows": []}, DLL, 123)
        self.assertEqual(absent["status"], "not_loaded")
        with self.assertRaises(m.ObserverError):
            m.resolve_module({"complete": False, "rows": []}, DLL, 123)
        rows = Modules().rows
        with self.assertRaises(m.ObserverError):
            m.resolve_module({"complete": True, "rows": rows+rows}, DLL, 123)
        with self.assertRaises(m.ObserverError):
            m.resolve_module({"complete": True, "rows": [{**rows[0], "path": EXE}]}, DLL, 123)

    def test_truncated_inventory_never_claims_unique_module(self):
        m = self.module(); clock = Clock()
        rows = Modules().rows * 257; api = Modules(rows)
        result = m.snapshot_modules(api, 123, 1.0, clock=clock, sleep=clock.sleep)
        self.assertFalse(result["complete"]); self.assertEqual(len(result["rows"]), 256)
        self.assertEqual(len(api.closed), 1)

    def test_every_rpm_has_policy_query_and_same_reader(self):
        b = self.bound(); result = b.read_rva(0x1000, 16)
        self.assertEqual(result["data"], b"A"*16)
        self.assertEqual(b.reader.reads, [(0x67001000, 16)])
        self.assertEqual(b.reader.queries, [0x67001000])
        self.assertTrue(b.reads[0]["read_attempted"])
        self.assertEqual(b.policy_queries[0]["region"]["allocation_base"], 0x67000000)

    def test_guard_noaccess_reserve_private_and_crossregion_do_not_rpm(self):
        m = self.module()
        for delta in ({"protect": 0x120}, {"protect": 1}, {"state": 0x2000},
                      {"type": 0x20000}, {"allocation_base": 0x66000000},
                      {"region_size": 8}):
            reader = Reader(region=delta); b = self.bound(reader)
            with self.subTest(delta=delta), self.assertRaises(m.ObserverError): b.read_rva(0, 16)
            self.assertEqual(reader.reads, [])
            self.assertTrue(b.reads[0]["read_not_attempted"])
            self.assertIsNone(b.reads[0]["winerror"])

    def test_native_partial_transfer_keeps_actual_prefix_and_winerror(self):
        r = Reader(read_result={"data": b"ABC", "transferred_bytes": 3, "success": False, "winerror": 299})
        b = self.bound(r); actual = b.read_rva(0, 16)
        self.assertEqual(actual["data"], b"ABC"); self.assertEqual(actual["winerror"], 299)
        self.assertEqual(b.reads[0]["hex"], "414243")
        self.assertEqual(b.reads[0]["transferred_bytes"], 3)

    def test_identity_contradiction_stops_before_rpm_and_is_sticky(self):
        m = self.module(); r = Reader(change_identity_at=2); b = self.bound(r)
        with self.assertRaises(Exception): b.read_rva(0, 16)
        self.assertEqual(r.reads, []); self.assertEqual(b.fatal["code"], "PROCESS_IDENTITY_MISMATCH")
        r.change_identity_at = 0
        with self.assertRaises(Exception): b.read_rva(0, 16)
        self.assertEqual(r.reads, [])

    def test_query_metadata_can_show_nonexecutable_without_rpm(self):
        r = Reader(region={"protect": 4}); b = self.bound(r)
        self.assertEqual(b.query_va(0x67001000)["protect"], 4)
        self.assertEqual(r.reads, [])

    def test_samples_are_wx_complete_and_small_index_only(self):
        with temporary_fixture() as folder:
            out = Path(folder)/"out"; reader = Reader()
            result, _ = self.collect(out, reader=reader)
            self.assertEqual(result["status"], "completed")
            self.assertTrue(reader.closed)
            self.assertEqual([x["status"] for x in result["samples"]], ["completed", "completed"])
            payload = json.loads((out/result["samples"][0]["file"]).read_text(encoding="utf-8"))
            self.assertEqual(payload["inspection"]["reads"][0]["hex"], "41"*16)
            self.assertFalse("inspection" in result["samples"][0])
            self.assertEqual(json.loads((out/"result.json").read_text(encoding="utf-8")), result)

    def test_each_sample_resolves_new_aslr_base_and_new_cache(self):
        class Reloaded(Modules):
            def snapshot(self, pid):
                value = super().snapshot(pid)
                base = 0x67000000 + (self.opens-1)*0x1000000
                self.rows[0] = {**self.rows[0], "base": base}
                return value
        class ReloadReader(Reader):
            def query(self, address):
                self.region.update(base_address=address & ~0xffffff, allocation_base=address & ~0xffffff)
                return super().query(address)
        with temporary_fixture() as folder:
            result, model = self.collect(Path(folder)/"out", reader=ReloadReader(), modules=Reloaded())
            self.assertEqual(model.calls, [0x67000000, 0x68000000])
            self.assertEqual(result["status"], "completed")

    def test_late_sample_failure_preserves_first_file_and_future_denominator(self):
        with temporary_fixture() as folder:
            out = Path(folder)/"out"
            result, _ = self.collect(out, model=Model(fail_at=2), config=request(sample_offsets_ms=[0, 25, 50]))
            self.assertEqual(result["status"], "partial")
            self.assertTrue((out/result["samples"][0]["file"]).is_file())
            self.assertEqual(result["samples"][1]["status"], "failed")
            self.assertEqual(result["samples"][2]["status"], "completed")

    def test_exit_keeps_prefix_and_unattempted_rows(self):
        with temporary_fixture() as folder:
            r = Reader(exit_at=8)
            result, _ = self.collect(Path(folder)/"out", reader=r, config=request(sample_offsets_ms=[0, 25, 50]))
            self.assertEqual(result["status"], "partial")
            self.assertTrue(any(x["status"] == "unattempted" for x in result["samples"]))
            self.assertEqual(result["error"]["code"], "PROCESS_EXITED")

    def test_deadline_keeps_unattempted_and_closes_reader(self):
        class Slow(Model):
            def inspect_exports(self, *args, **kwargs):
                self.clock.now += 2
                return super().inspect_exports(*args, **kwargs)
        m = self.module(); memory, regions, _ = m.load_frozen_support(); clock=Clock(); reader=Reader()
        with temporary_fixture() as folder:
            result = m.collect_samples(request(), Path(folder)/"out", reader, Modules(), Slow(clock),
                                       memory, regions, clock=clock, sleep=clock.sleep)
            self.assertEqual(result["error"]["code"], "TIMEOUT")
            self.assertEqual(result["samples"][1]["status"], "unattempted"); self.assertTrue(reader.closed)

    def test_cleanup_error_does_not_erase_identity_error_or_prefix(self):
        with temporary_fixture() as folder:
            r = Reader(change_identity_at=2, close_error=True)
            result, _ = self.collect(Path(folder)/"out", reader=r)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"]["code"], "PROCESS_IDENTITY_MISMATCH")
            self.assertEqual(result["cleanup"]["errors"][0]["code"], "CLOSE_FAILED")
            self.assertFalse(result["cleanup"]["process_handle_closed"])

    def test_existing_output_has_no_mutation(self):
        with temporary_fixture() as folder:
            out = Path(folder)/"out"; out.mkdir(); (out/"old").write_bytes(b"old")
            m = self.module()
            with self.assertRaises(m.ObserverError): self.collect(out)
            self.assertEqual(sorted(x.name for x in out.iterdir()), ["old"])
            self.assertEqual((out/"old").read_bytes(), b"old")



    def test_snapshot_failure_preserves_specific_native_error(self):
        m = self.module(); clock = Clock()
        inventory = m.snapshot_modules(Modules(failures=10), 123, 1.0, clock=clock, sleep=clock.sleep)
        with self.assertRaises(m.ObserverError) as raised:
            m.resolve_module(inventory, DLL, 123)
        self.assertEqual(raised.exception.code, "MODULE_SNAPSHOT_FAILED")
        self.assertEqual(raised.exception.winerror, 24)

    def test_final_source_failure_closes_all_handles_and_keeps_first_error(self):
        m = self.module()
        class Source:
            def __init__(self, bad=False): self.bad, self.closed, self.verified = bad, False, False
            def receipt(self): return {"path": "synthetic", "sha256": "a"*64}
            def verify(self):
                self.verified = True
                if self.bad: raise m.ObserverError("SOURCE_CHANGED", "source changed")
            def close(self): self.closed = True
        first, second = Source(True), Source()
        result = {"status": "partial", "error": {"code": "TIMEOUT", "message": "first"},
                  "cleanup": {"errors": []}}
        self.assertTrue(callable(getattr(m, "finalize_sources", None)), "Source finalizer is not implemented")
        m.finalize_sources(result, [first, second], [])
        self.assertTrue(first.closed and second.closed and second.verified)
        self.assertEqual(result["error"]["code"], "TIMEOUT")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["sources"][0]["verified_stable"])
        self.assertTrue(result["sources"][1]["verified_stable"])



    def test_policy_raw_bytes_reference_exact_model_read_without_duplication(self):
        m = self.module()
        native = [{"rva": "0x0", "requested_bytes": 3, "transferred_bytes": 3,
                   "hex": "414243", "sha256": hashlib.sha256(b"ABC").hexdigest()}]
        inspection = {"reads": [{"rva": "0x0", "requested_size_bytes": 3,
                      "transferred_bytes": 3, "hex": "414243",
                      "sha256": hashlib.sha256(b"ABC").hexdigest()}]}
        self.assertTrue(callable(getattr(m, "compact_reads", None)), "Lossless raw-reference binding is missing")
        compact = m.compact_reads(native, inspection)
        self.assertNotIn("hex", compact[0])
        self.assertEqual(compact[0]["actual_bytes_reference"], "inspection.reads[0].hex")
        self.assertEqual(native[0]["hex"], "414243")
        unmatched = m.compact_reads(native, {"reads": []})
        self.assertEqual(unmatched[0]["hex"], "414243")



    def test_cli_unknown_arguments_return_structured_failure_without_win32(self):
        import subprocess
        result = subprocess.run([sys.executable, "-B", str(HERE/"observe.py"), "--pid", "123"],
                                capture_output=True, encoding="utf-8", errors="strict", timeout=5)
        self.assertNotEqual(result.returncode, 0)
        try: value = json.loads(result.stdout)
        except ValueError: self.fail("CLI validation did not retain structured UTF-8 failure JSON")
        self.assertEqual(value["error"]["code"], "INVALID_ARGUMENTS")
        self.assertIsNone(value["result_file"])



    def test_wrong_pid_inventory_cannot_prove_module_absent(self):
        m = self.module(); clock = Clock()
        api = Modules([{"pid": 999, "name": "other.dll", "path": DLL,
                        "base": 0x100000, "size_bytes": 4096}])
        inventory = m.snapshot_modules(api, 123, 1.0, clock=clock, sleep=clock.sleep)
        self.assertFalse(inventory["complete"])
        with self.assertRaises(m.ObserverError): m.resolve_module(inventory, DLL, 123)
        self.assertEqual(len(api.closed), 1)



    def test_final_wx_publication_failure_returns_real_prefix_and_first_error(self):
        m = self.module(); memory, regions, _ = m.load_frozen_support(); clock = Clock()
        class TimeoutsAfterPrefix(Model):
            def inspect_exports(self, *args, **kwargs):
                if self.calls: clock.now = 2.0
                return super().inspect_exports(*args, **kwargs)
        class BlockFinal(m.Publisher):
            def progress(self, result):
                if result.get("ended_utc") is not None and not (self.out/"result.json").exists():
                    (self.out/"result.json").write_bytes(b"collision")
                return super().progress(result)
        with temporary_fixture() as folder:
            out=Path(folder)/"out"; publisher=BlockFinal(out); reader=Reader()
            try:
                result=m.collect_samples(request(sample_offsets_ms=[0,25,50]), out, reader,
                    Modules(), TimeoutsAfterPrefix(), memory, regions, clock=clock,
                    sleep=clock.sleep, publisher=publisher)
            except Exception as error:
                self.fail("Final publication erased actual result instead of returning it: "+str(error))
            self.assertEqual(result["error"]["code"], "TIMEOUT")
            self.assertEqual(result["samples"][0]["status"], "completed")
            self.assertTrue((out/result["samples"][0]["file"]).is_file())
            self.assertEqual(result["samples"][2]["status"], "unattempted")
            self.assertTrue(result["cleanup"]["process_handle_closed"])
            self.assertEqual((out/"result.json").read_bytes(), b"collision")
            summary=m.summary(result,publisher.files.get("result.json"))
            self.assertIsNone(summary["result_file"])
            self.assertEqual(summary["samples"], result["samples"])
            self.assertTrue(result["publication_errors"])

    def test_final_generic_identity_error_cannot_downgrade_prior_failed(self):
        m=self.module(); memory,regions,_=m.load_frozen_support(); clock=Clock()
        class IdentityLater(Reader):
            after_model=False
            allowed_after=False
            fatal_sent=False
            def identity(self):
                row=super().identity()
                if self.fatal_sent: raise OSError("late generic identity error")
                if self.after_model:
                    if not self.allowed_after:
                        self.allowed_after=True
                    else:
                        self.fatal_sent=True
                        row["creation_filetime"]="134369128310367120"
                return row
        reader=IdentityLater()
        class First(Model):
            def inspect_exports(self,*args,**kwargs):
                row=super().inspect_exports(*args,**kwargs)
                reader.after_model=True
                return row
        with temporary_fixture() as folder:
            result=m.collect_samples(request(sample_offsets_ms=[0,25,50]),Path(folder)/"out",
                reader,Modules(),First(),memory,regions,clock=clock,sleep=clock.sleep)
            self.assertEqual(result["status"],"failed")
            self.assertEqual(result["error"]["code"],"PROCESS_IDENTITY_MISMATCH")
            self.assertEqual(result["samples"][0]["status"],"completed")
            self.assertEqual(result["samples"][1]["status"],"unattempted")
            self.assertTrue(result["cleanup"]["process_handle_closed"])



    def test_transient_identity_fatal_survives_sample_wx_failure(self):
        m=self.module(); memory,regions,_=m.load_frozen_support(); clock=Clock()
        class Once(Reader):
            def identity(self):
                row=super().identity()
                if self.identities == 12: row["creation_filetime"]="134369128310367120"
                return row
        class BlockSecond(m.Publisher):
            def write(self,name,value,**kwargs):
                if name == "sample-001.json" and not (self.out/name).exists():
                    (self.out/name).write_bytes(b"collision")
                return super().write(name,value,**kwargs)
        with temporary_fixture() as folder:
            out=Path(folder)/"out"; publisher=BlockSecond(out); reader=Once()
            result=m.collect_samples(request(sample_offsets_ms=[0,25,50]),out,reader,
                Modules(),Model(),memory,regions,clock=clock,sleep=clock.sleep,publisher=publisher)
            self.assertEqual(result["error"]["code"],"PROCESS_IDENTITY_MISMATCH")
            self.assertEqual(result["status"],"failed")
            self.assertEqual(json.loads((out/"result.json").read_text(encoding="utf-8"))["status"],"failed")
            self.assertEqual(result["samples"][0]["status"],"completed")
            self.assertEqual(result["samples"][1]["status"],"failed")
            self.assertEqual(result["samples"][2]["status"],"unattempted")
            self.assertTrue(reader.closed)
            self.assertEqual(result["publication_errors"][0]["file"],"sample-001.json")
            self.assertEqual((out/"sample-001.json").read_bytes(),b"collision")


if __name__ == "__main__":
    unittest.main(verbosity=2)
