"""Pinned 104-byte x86 writer under bounded CPU emulation, never native execution."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ENTRY = 0x480230
BODY = bytes.fromhex('8b442404db4424088b51088d048003c003c003c003d0dd1adb44240cdd5a088b54240885d274053b5134750d8b54240c85d274093b5138740433d2eb05ba03000000568b71088854301c8b5108dd04028b4908dd44020803d08d440810d9c9d9185ed95804c20c00')
BODY_SHA256 = 'd7daa514e39357d058792f132bfbc084f1b03d8f67a17668af8839eb8da6aa38'
IMAGE_SHA256 = '50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992'
IMAGE_SIZE = 14454272
IMAGE_RAW_OFFSET = 0x7f630
MODEL_SHA256 = '88a06ed8dd7cfc5c016d860931a67a5f44b1a3d0d8bbf0c059a6dd1b5700fe87'
PINS_SHA256 = '558c304721275cfb09f749ef38366e7567697b4e00b1447f7f6f9b1894cb73ff'
INSTRUCTIONS = {ENTRY + offset: size for offset, size in (
    (0,4),(4,4),(8,3),(0xb,3),(0xe,2),(0x10,2),(0x12,2),(0x14,2),(0x16,2),(0x18,4),
    (0x1c,3),(0x1f,4),(0x23,2),(0x25,2),(0x27,3),(0x2a,2),(0x2c,4),(0x30,2),(0x32,2),
    (0x34,3),(0x37,2),(0x39,2),(0x3b,2),(0x3d,5),(0x42,1),(0x43,3),(0x46,4),(0x4a,3),
    (0x4d,3),(0x50,3),(0x53,4),(0x57,2),(0x59,4),(0x5d,2),(0x5f,2),(0x61,1),(0x62,3),(0x65,3))}
STEP_BUDGET = 128
TIMEOUT_US = 100000
PAGE = 4096
SENTINEL = 0x60001000
BAD_COMPONENT = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
RESERVED = re.compile(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_path(value: str) -> Path:
    if type(value) is not str or not value or len(value) > 4096 or '\x00' in value:
        raise ValueError('Expected a bounded local path')
    if any(part in ('.', '..') for part in re.split(r'[\\/]', value)):
        raise ValueError('Dot path components are not accepted')
    selected = Path(value)
    if os.name == 'nt' and (selected.anchor and not selected.is_absolute() or selected.is_absolute() and not re.match(r'^[A-Za-z]:[\\/]', value)):
        raise ValueError('Only local drive paths are accepted on Windows')
    for part in selected.parts:
        if part != selected.anchor and (part.endswith(('.', ' ')) or BAD_COMPONENT.search(part) or RESERVED.match(part)):
            raise ValueError('Aliased or special path component')
    return selected.absolute()


def check_chain(selected: Path) -> None:
    for entry in (selected, *selected.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Reparse points, symlinks and junctions are not accepted')
    if os.path.normcase(str(selected.resolve(strict=True))) != os.path.normcase(str(selected)):
        raise ValueError('Resolved path alias')


def stable_read(selected: Path, limit: int) -> bytes:
    check_chain(selected)
    entry = selected.stat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or not 0 <= entry.st_size <= limit:
        raise ValueError('Input must be a bounded ordinary single-link file')
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink)
    state = lambda s: (*identity(s), s.st_ctime_ns)
    with selected.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if identity(entry) != identity(opened):
            raise ValueError('Input changed before opening')
        data = stream.read(limit + 1)
        closed = os.fstat(stream.fileno())
    check_chain(selected)
    final = selected.stat()
    # Windows path.stat and fstat have different ctime meanings. Each API is
    # compared with itself; only common identity fields cross the API boundary.
    if state(entry) != state(final) or state(opened) != state(closed) or identity(final) != identity(closed) or len(data) != entry.st_size:
        raise ValueError('Input changed during retained-handle read')
    return data


def identity(path: Path, data: bytes) -> dict:
    return {'path': str(path), 'size_bytes': len(data), 'sha256': sha(data)}


def extract_body(data: bytes) -> bytes:
    if len(data) != IMAGE_SIZE or sha(data) != IMAGE_SHA256:
        raise ValueError('Fixed analysis image identity mismatch')
    # The full source hash pins this PE32 mapping, independently of flat-RVA
    # captures. This offset is deliberately not the RVA 0x80230.
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    optional = pe + 24
    if data[:2] != b'MZ' or data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] != 0x14c or struct.unpack_from('<H', data, optional)[0] != 0x10b or struct.unpack_from('<I', data, optional+28)[0] != 0x400000:
        raise ValueError('Pinned PE32 header mismatch')
    body = data[IMAGE_RAW_OFFSET:IMAGE_RAW_OFFSET + len(BODY)]
    if body != BODY or sha(body) != BODY_SHA256:
        raise ValueError('Fixed body bytes mismatch')
    return body


def build_cases(model_sha256: str) -> list[dict]:
    if model_sha256 != MODEL_SHA256:
        raise ValueError('Freeze the exact independent model before constructing cases')
    result = []
    for width, height in ((2,2), (3,2), (16,16)):
        points = ((0,0), (width,0), (0,height), (width,height), (0,1), (width,1), (1,0), (1,height), (1,1))
        for index, (x, y) in enumerate(points):
            node_id = 0 if index % 2 == 0 else 1
            capacity = 1 if node_id == 0 and index == 0 else 3
            result.append({'id': f'w{width}h{height}-p{index}-n{node_id}', 'width': width, 'height': height,
                           'x': x, 'y': y, 'node_id': node_id, 'capacity': capacity})
    for x, y in ((0,0), (16,16), (0,1), (1,1)):
        result.append({'id': f'w16h16-max-{x}-{y}', 'width': 16, 'height': 16,
                       'x': x, 'y': y, 'node_id': 288, 'capacity': 289})
    assert len(result) <= 128
    return result


def compare_storage(actual: bytes, expected: bytes) -> dict:
    differences = [i for i, (a, b) in enumerate(zip(actual, expected)) if a != b]
    return {'matched': actual == expected, 'actual_sha256': sha(actual), 'expected_sha256': sha(expected),
            'actual_size_bytes': len(actual), 'expected_size_bytes': len(expected),
            'different_byte_count': len(differences) + abs(len(actual) - len(expected)), 'first_differences': differences[:64]}


class CpuBoundary:
    def __init__(self, base: int, size: int, node_id: int, stack: int):
        self.target = base + 40 * node_id
        self.stack = stack
        if not 40 <= size <= 40 * 289 or size % 40 or not 0 <= node_id < size // 40:
            raise ValueError('Invalid bounded storage')
        self.steps = 0
        self.pcs = []
        self.writes = []

    def check_code(self, address: int, size: int) -> None:
        if INSTRUCTIONS.get(address) != size or self.steps >= STEP_BUDGET:
            raise ValueError('Unknown instruction address/size or step budget reached')
        self.steps += 1
        self.pcs.append(hex(address))

    def check_write(self, address: int, size: int) -> None:
        intervals = ((self.target, self.target+24), (self.target+28, self.target+29), (self.stack-4, self.stack))
        if type(size) is not int or not 1 <= size <= 8 or not any(start <= address and address+size <= end for start, end in intervals):
            raise ValueError('Write outside observed fields or the single PUSH ESI slot')
        if len(self.writes) >= 128:
            raise ValueError('Write event budget reached')
        self.writes.append({'address': hex(address), 'size_bytes': size})


def read_x87(cpu, keys: dict) -> dict:
    result = {name: int(cpu.reg_read(key)) for name, key in keys.items()}
    result['top'] = (result['status'] >> 11) & 7
    return result


def initialize_x87(cpu, keys: dict) -> dict:
    requested = {'control': 0x37f, 'status': 0, 'tag': 0xffff}
    for name, value in requested.items():
        cpu.reg_write(keys[name], value)
    observed = read_x87(cpu, keys)
    if any(observed[name] != value for name, value in requested.items()) or observed['top'] != 0:
        raise ValueError('Explicit x87 control/status/tag roundtrip is unsupported or mismatched')
    return observed


def unicorn_pins() -> list[dict]:
    pins_data = stable_read(HERE / 'unicorn-pins.json', 65536)
    if sha(pins_data) != PINS_SHA256:
        raise ValueError('Dependency pin manifest changed')
    return json.loads(pins_data.decode('utf-8', errors='strict'))['files']


def validate_runtime(runtime: Path, pins: list[dict]) -> list[dict]:
    """Reject every unregistered file/directory before Python resolves imports."""
    check_chain(runtime)
    expected_files = {row['file'] for row in pins}
    expected_dirs = {parent.as_posix() for row in pins for parent in Path(row['file']).parents if str(parent) != '.'}
    files, directories, pending = set(), set(), [runtime]
    while pending:
        directory = pending.pop()
        check_chain(directory)
        for path in directory.iterdir():
            check_chain(path)
            relative = path.relative_to(runtime).as_posix()
            if path.is_dir():
                if relative not in expected_dirs: raise ValueError('Runtime inventory contains an unregistered directory')
                directories.add(relative); pending.append(path)
            elif path.is_file():
                if relative not in expected_files: raise ValueError('Runtime inventory contains an unregistered file')
                files.add(relative)
            else:
                raise ValueError('Runtime inventory contains a non-regular entry')
    if files != expected_files or directories != expected_dirs:
        raise ValueError('Runtime inventory does not equal the fixed dependency pins')
    identities = []
    for row in pins:
        path = runtime / row['file']
        data = stable_read(path, 16 * 1024 * 1024)
        if len(data) != row['size_bytes'] or sha(data) != row['sha256']:
            raise ValueError('Pinned Unicorn file mismatch: ' + row['file'])
        identities.append(identity(path, data))
    return identities


def stage_unicorn(module_path: Path, runtime: Path) -> dict:
    """Cache all pinned input bytes first, then create a clean owned package."""
    check_chain(module_path)
    check_chain(runtime.parent)
    if os.path.lexists(runtime): raise ValueError('Runtime staging directory already exists')
    pins = unicorn_pins()
    cached, source_files = [], []
    for row in pins:
        path = module_path / row['file']
        data = stable_read(path, 16 * 1024 * 1024)
        if len(data) != row['size_bytes'] or sha(data) != row['sha256']:
            raise ValueError('Pinned Unicorn file mismatch: ' + row['file'])
        cached.append((row['file'], data))
        source_files.append(identity(path, data))
    runtime.mkdir()
    for relative, data in cached:
        path = runtime / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        save_new(path, data)
    staged_files = validate_runtime(runtime, pins)
    return {'source_files':source_files, 'staged_files':staged_files}


def load_unicorn(runtime: Path, cache_prefix: Path) -> tuple:
    if sys.platform != 'win32':
        raise ValueError('This dependency pin covers the reviewed Windows Unicorn build only')
    pins = unicorn_pins()
    validate_runtime(runtime, pins)
    if any(name == 'unicorn' or name.startswith('unicorn.') for name in sys.modules):
        raise ValueError('A preloaded Unicorn module is not accepted')
    # Force the reviewed DLL location; do not use an inherited library override.
    # The original installation is never placed on the import search path.
    os.environ['LIBUNICORN_PATH'] = str(runtime / 'unicorn' / 'lib')
    sys.pycache_prefix = str(cache_prefix)
    sys.path.insert(0, str(runtime))
    uc = importlib.import_module('unicorn')
    x86 = importlib.import_module('unicorn.x86_const')
    core = importlib.import_module('unicorn.unicorn_py3.unicorn')
    if uc.__version__ != '2.1.4' or tuple(uc.uc_version())[:2] != (2,1):
        raise ValueError('Unicorn API version mismatch')
    expected_dll = (runtime / 'unicorn' / 'lib' / 'unicorn.dll').resolve(strict=True)
    dll = Path(core.uclib._name).resolve(strict=True)
    if os.path.normcase(str(dll)) != os.path.normcase(str(expected_dll)):
        raise ValueError('Loaded Unicorn DLL origin differs from the reviewed pin')
    origins = []
    for name, module in list(sys.modules.items()):
        if name == 'unicorn' or name.startswith('unicorn.'):
            path = Path(module.__file__).absolute()
            relative = path.relative_to(runtime).as_posix()
            if relative not in {row['file'] for row in pins}:
                raise ValueError('Unregistered Unicorn Python module origin')
            origins.append({'module':name,'path':str(path)})
    validate_runtime(runtime, pins)
    return uc, x86, origins


def run_case(uc, x86, body: bytes, case: dict, model) -> dict:
    started = time.monotonic()
    storage = bytes((index * 37 + 0xa5) & 255 for index in range(case['capacity'] * 40))
    expected = model(storage, case['node_id'], case['x'], case['y'], case['width'], case['height'])
    row = {'id': case['id'], 'status': 'failed', 'case': case, 'storage_before_hex': storage.hex(),
           'emulation_started': False, 'emulation_returned': False,
           'expected_sha256': sha(expected), 'actual_after_hex': None, 'error': None}
    cpu = None
    boundary = None
    hooks = []
    try:
        cpu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        code_page = ENTRY & -PAGE
        cpu.mem_map(code_page, PAGE, uc.UC_PROT_ALL)
        cpu.mem_write(code_page, b'\xcc' * PAGE)
        cpu.mem_write(ENTRY, body)
        cpu.mem_protect(code_page, PAGE, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        cpu.mem_map(SENTINEL, PAGE, uc.UC_PROT_ALL)
        cpu.mem_write(SENTINEL, b'\xcc' * PAGE)
        cpu.mem_protect(SENTINEL, PAGE, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        context_page = 0x20001000
        context = context_page + 0x100
        context_page_data = bytearray(b'\x79' * PAGE)
        pages = (len(storage) + 64 + PAGE - 1) // PAGE
        data_page, data_size = 0x30001000, pages * PAGE
        record_base = data_page + data_size - len(storage)
        struct.pack_into('<I', context_page_data, 0x108, record_base)
        struct.pack_into('<II', context_page_data, 0x134, case['width'], case['height'])
        cpu.mem_map(context_page, PAGE, uc.UC_PROT_ALL)
        cpu.mem_write(context_page, bytes(context_page_data))
        cpu.mem_protect(context_page, PAGE, uc.UC_PROT_READ)
        cpu.mem_map(data_page, data_size, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        data_before = b'\xd3' * (data_size-len(storage)) + storage
        cpu.mem_write(data_page, data_before)
        stack_page = 0x50001000
        stack = stack_page + PAGE - 0x100
        stack_before = bytearray(b'\xb7' * PAGE)
        struct.pack_into('<IIII', stack_before, stack-stack_page, SENTINEL, case['node_id'], case['x'], case['y'])
        cpu.mem_map(stack_page, PAGE, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        cpu.mem_write(stack_page, bytes(stack_before))
        reg_names = ('EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP','EFLAGS')
        reg_keys = {name: getattr(x86, 'UC_X86_REG_' + name) for name in reg_names}
        requested = {'EAX':0x11111111,'EBX':0x22334455,'ECX':context,'EDX':0x33445566,
                     'ESI':0x44667788,'EDI':0x55778899,'EBP':0x668899aa,'ESP':stack,'EIP':ENTRY,'EFLAGS':0x202}
        for name, value in requested.items(): cpu.reg_write(reg_keys[name], value)
        keys = {name: getattr(x86, constant) for name, constant in
                (('control','UC_X86_REG_FPCW'), ('status','UC_X86_REG_FPSW'), ('tag','UC_X86_REG_FPTAG'))}
        row['x87_before'] = initialize_x87(cpu, keys)
        row['registers_before'] = {name: int(cpu.reg_read(key)) for name, key in reg_keys.items()}
        boundary = CpuBoundary(record_base, len(storage), case['node_id'], stack)
        hook_errors = []
        invalid_accesses = []
        def code_hook(engine, address, size, _):
            try: boundary.check_code(address, size)
            except Exception as error:
                hook_errors.append(str(error)); engine.emu_stop()
        def write_hook(engine, access, address, size, value, _):
            try: boundary.check_write(address, size)
            except Exception as error:
                hook_errors.append(str(error)); engine.emu_stop()
        def invalid_hook(engine, access, address, size, value, _):
            invalid_accesses.append({'access':access, 'address':hex(address), 'size_bytes':size})
            return False
        hooks.append(cpu.hook_add(uc.UC_HOOK_CODE, code_hook))
        hooks.append(cpu.hook_add(uc.UC_HOOK_MEM_WRITE, write_hook))
        hooks.append(cpu.hook_add(uc.UC_HOOK_MEM_INVALID, invalid_hook))
        row['layout'] = {'context':hex(context), 'record_base':hex(record_base), 'record_size_bytes':len(storage),
                         'record_mapping':{'base':hex(data_page),'size_bytes':data_size}, 'entry_esp':hex(stack),
                         'sentinel':hex(SENTINEL), 'guard_policy':'Unmapped pages immediately before/after context, data and stack; data prefix is a checked canary',
                         'context_fields':{'0x8':hex(record_base),'0x34':case['width'],'0x38':case['height']}}
        native_error = None
        row['mapped_regions_before'] = [list(region) for region in cpu.mem_regions()]
        try:
            # The official C header specifies microseconds; Python forwards
            # this integer unchanged, despite its milliseconds docstring.
            row['emulation_started'] = True
            cpu.emu_start(ENTRY, SENTINEL, timeout=TIMEOUT_US, count=STEP_BUDGET)
            row['emulation_returned'] = True
        except Exception as error:
            native_error = str(error)
        actual = bytes(cpu.mem_read(record_base, len(storage)))
        row['actual_after_hex'] = actual.hex()
        row['registers_after'] = {name:int(cpu.reg_read(key)) for name,key in reg_keys.items()}
        row['x87_after'] = read_x87(cpu, keys)
        row['invalid_accesses'] = invalid_accesses
        row['writes'] = boundary.writes
        row['executed_pcs'] = boundary.pcs
        row['steps'] = boundary.steps
        row['hook_errors'] = hook_errors
        row['cpu_error'] = native_error
        row['comparison'] = compare_storage(actual, expected)
        data_after = bytes(cpu.mem_read(data_page, data_size))
        stack_after = bytes(cpu.mem_read(stack_page, PAGE))
        expected_stack = bytearray(stack_before)
        struct.pack_into('<I', expected_stack, stack-stack_page-4, requested['ESI'])
        after = row['registers_after']
        row['mapped_regions_after'] = [list(region) for region in cpu.mem_regions()]
        row['checks'] = {
            'sentinel_reached':after['EIP'] == SENTINEL, 'ret12_stack':after['ESP'] == stack+16,
            'callee_saved':all(after[name] == requested[name] for name in ('EBX','ESI','EDI','EBP')),
            'context_unchanged':bytes(cpu.mem_read(context_page,PAGE)) == bytes(context_page_data),
            'data_prefix_unchanged':data_after[:data_size-len(storage)] == data_before[:data_size-len(storage)],
            'stack_only_push_slot_changed':stack_after == bytes(expected_stack),
            'code_unchanged':bytes(cpu.mem_read(ENTRY,len(body))) == body,
            'mapping_permissions_unchanged':row['mapped_regions_before'] == row['mapped_regions_after'],
            'x87_control_unchanged':row['x87_after']['control'] == row['x87_before']['control'],
            'x87_empty_after':row['x87_after']['top'] == 0 and row['x87_after']['tag'] == 0xffff,
            'all_storage_matches':row['comparison']['matched'], 'no_hook_or_cpu_error':not hook_errors and not invalid_accesses and native_error is None}
        row['surrounding_memory'] = {'data_prefix_before_sha256':sha(data_before[:data_size-len(storage)]),
            'data_prefix_after_sha256':sha(data_after[:data_size-len(storage)]), 'context_before_sha256':sha(bytes(context_page_data)),
            'context_after_sha256':sha(bytes(cpu.mem_read(context_page,PAGE))), 'stack_before_sha256':sha(bytes(stack_before)),
            'stack_after_sha256':sha(stack_after), 'stack_expected_after_sha256':sha(bytes(expected_stack))}
        offset = case['node_id'] * 40
        row['changed_offsets_in_record'] = [i for i in range(40) if storage[offset+i] != actual[offset+i]]
        wrong_flag = bytearray(expected); wrong_flag[offset+28] = 0 if expected[offset+28] == 3 else 3
        wrong_coordinate = bytearray(expected); struct.pack_into('<d', wrong_coordinate, offset, case['x'] + 1)
        row['negative_controls'] = {'wrong_flag_rejected':actual != bytes(wrong_flag), 'wrong_coordinate_rejected':actual != bytes(wrong_coordinate)}
        if not all(row['checks'].values()) or not all(row['negative_controls'].values()):
            raise ValueError('CPU observation, preservation, model or negative-control check failed')
        row['status'] = 'completed'
    except (Exception, KeyboardInterrupt) as error:
        row['error'] = {'code':'CPU_CASE_FAILED','message':str(error)[:2048]}
        # Actual bytes, when already observed, remain in the failed row. No
        # expected model output is substituted for a missing CPU observation.
    finally:
        row['duration_ms'] = round((time.monotonic()-started)*1000,3)
        if boundary is not None:
            row.setdefault('writes', boundary.writes); row.setdefault('steps',boundary.steps)
        if cpu is not None:
            for hook in hooks:
                try: cpu.hook_del(hook)
                except Exception as error:
                    row.setdefault('cleanup_errors', []).append(str(error)[:512])
                    row['status'] = 'failed'
                    if row['error'] is None: row['error'] = {'code':'CPU_HOOK_CLEANUP_FAILED','message':str(error)[:2048]}
    return row


def encoded(value: dict) -> bytes:
    data = (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',',':')) + '\n').encode('utf-8', errors='strict')
    if len(data) > 8*1024*1024:
        raise ValueError('Receipt exceeds 8 MiB')
    return data


def save_new(path: Path, data: bytes) -> None:
    check_chain(path.parent)
    with path.open('xb') as stream:
        if stream.write(data) != len(data): raise OSError('Short new evidence write')
        stream.flush(); os.fsync(stream.fileno())
    if stable_read(path, max(len(data),1)) != data: raise OSError('New evidence verification failed')


def checkpoint(out: Path, result: dict) -> None:
    temporary = out / 'progress.tmp'
    save_new(temporary, encoded(result))
    destination = out / 'progress.json'
    if os.path.lexists(destination):
        check_chain(destination)
        if destination.stat().st_nlink != 1: raise ValueError('Checkpoint hardlink rejected')
    os.replace(temporary, destination)


class Parser(argparse.ArgumentParser):
    def error(self, message): raise ValueError(message)


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None: raise ValueError('Repeated option: '+str(option_string))
        setattr(namespace, self.dest, values)


def main(argv=None) -> int:
    result = {'schema_version':1,'kind':'node_record_bounded_cpu_replay','status':'failed',
              'observation_kind':'bounded_cpu_emulation','target_execution':'not_run','native_call':False,
              'natural_fpu_state_verified':False,'constructor_initialization_verified':False,
              'limits':{'dimensions':'2..16','capacity':'1..289','case_limit':128,'instruction_limit':STEP_BUDGET,
                        'timeout_microseconds_per_case':TIMEOUT_US,'unknown_fields_preserved':'record bytes 24..27 and 29..39'},
              'body':{'entry':hex(ENTRY),'size_bytes':len(BODY),'sha256':BODY_SHA256},
              'started_utc':datetime.now(timezone.utc).isoformat(),'rows':[],'error':None}
    out = None
    registered = []
    try:
        parser = Parser(description=__doc__,allow_abbrev=False)
        for option in ('module-path','image','out'): parser.add_argument('--'+option,required=True,action=Once)
        args = parser.parse_args(argv)
        module_path, image, destination = (checked_path(value) for value in (args.module_path,args.image,args.out))
        check_chain(destination.parent)
        if os.path.lexists(destination): raise ValueError('Output directory already exists')
        # Validate every immutable input before creating outputs or importing
        # any third-party binding. Candidate bytes are frozen before cases.
        source = stable_read(image,16*1024*1024); body = extract_body(source)
        model_path = HERE / 'model.py'; model_data = stable_read(model_path,65536)
        if sha(model_data) != MODEL_SHA256: raise ValueError('Frozen model identity mismatch')
        own_path = Path(__file__).absolute(); own_data = stable_read(own_path,131072)
        pin_path = HERE / 'unicorn-pins.json'; pin_data = stable_read(pin_path,65536)
        if sha(pin_data) != PINS_SHA256: raise ValueError('Dependency pin manifest identity mismatch')
        registered = [identity(image,source),identity(model_path,model_data),identity(own_path,own_data),identity(pin_path,pin_data)]
        model_namespace = {'__name__':'node_record_frozen_candidate'}
        exec(compile(model_data.decode('utf-8',errors='strict'),str(model_path),'exec'),model_namespace)
        model = model_namespace['patch_node_record']
        result['inputs'] = registered
        cases = build_cases(sha(model_data))
        result['case_policy'] = '31 deterministic corner/edge/interior cases constructed after candidate freeze; regression scope, not unseen-input proof'
        result['rows'] = [{'id':case['id'],'status':'unattempted','case':case} for case in cases]
        result['declared_cases'] = len(cases)
        destination.mkdir()
        out = destination
        save_new(out/'body.bin',body); save_new(out/'model.py',model_data); save_new(out/'replay.py',own_data); save_new(out/'unicorn-pins.json',pin_data)
        checkpoint(out,result)
        runtime = out/'runtime'
        dependencies = stage_unicorn(module_path,runtime)
        registered.extend(dependencies['source_files'])
        registered.extend(dependencies['staged_files'])
        result['unicorn'] = {'version':None,'source_module_path':str(module_path),'loaded_module_path':str(runtime),
                             **dependencies,'timeout_units':'microseconds per official C header'}
        checkpoint(out,result)
        uc, x86, origins = load_unicorn(runtime,out/'unused-pycache')
        result['unicorn'].update({'version':uc.__version__,'api_version':list(uc.uc_version()),'loaded_origins':origins})
        checkpoint(out,result)
        for index, case in enumerate(cases):
            result['rows'][index] = {'id':case['id'],'status':'failed','case':case,'error':{'code':'INTERRUPTED','message':'Case did not finish'}}
            checkpoint(out,result)
            row = run_case(uc,x86,body,case,model)
            result['rows'][index] = row
            checkpoint(out,result)
            if row['status'] != 'completed': raise ValueError('Stopped after failed CPU case: '+case['id'])
        result['status'] = 'completed'
    except (Exception, KeyboardInterrupt) as error:
        result['status'] = 'failed'
        result['error'] = {'code':'NODE_RECORD_REPLAY_FAILED','message':str(error)[:2048]}
    finally:
        # Rehash each original input using a fresh retained-handle read. Input
        # identity drift fails the run without discarding prior CPU bytes.
        result['inputs_unchanged'] = True
        for row in registered:
            try:
                data = stable_read(Path(row['path']),max(row['size_bytes'],1))
                if len(data) != row['size_bytes'] or sha(data) != row['sha256']: raise ValueError('Input content changed')
            except Exception as error:
                result['inputs_unchanged'] = False; result['status'] = 'failed'
                if result['error'] is None: result['error'] = {'code':'INPUT_CHANGED','message':str(error)[:2048]}
        result['counts'] = {state:sum(row['status']==state for row in result['rows']) for state in ('completed','failed','unattempted')}
        result['ended_utc'] = datetime.now(timezone.utc).isoformat()
        if out is not None:
            try:
                checkpoint(out,result)
                save_new(out/'result.json',encoded(result))
            except Exception as error:
                result['status'] = 'failed'
                result['persistence_error'] = str(error)[:2048]
                if result['error'] is None: result['error'] = {'code':'PERSISTENCE_FAILED','message':str(error)[:2048]}
    sys.stdout.buffer.write(encoded(result)); sys.stdout.buffer.flush()
    return 0 if result['status']=='completed' else 1


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8',errors='strict')
    sys.stderr.reconfigure(encoding='utf-8',errors='strict')
    raise SystemExit(main())
