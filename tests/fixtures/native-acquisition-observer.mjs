// Script-only test observer. It reports synthetic identity and data, never opens a PID.
import {readFile, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
const [stateFile, role, mode, encodedArgs] = process.argv.slice(2);
const args = JSON.parse(encodedArgs), state = JSON.parse(await readFile(stateFile, 'utf8'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const arg = name => args[args.indexOf(name) + 1];
const now = () => new Date().toISOString();
const identity = () => ({pid: state.pid, executable: state.executable, creation_filetime: state.creation_filetime,
  exit_filetime: '0', exit_code: 259, alive: true, observed_utc: now()});
process.stderr.write('SYNTHETIC_SCRIPT_OBSERVER: no process HANDLE opened and no target PE executed.\n', 'utf8');
if (role === 'identity') {
  process.stdout.write(JSON.stringify(identity()) + '\n', 'utf8');
} else if (role === 'main') {
  if (mode === 'bad-json') { process.stdout.write('synthetic invalid JSON\n', 'utf8'); }
  else {
    const started = now(), prefix = arg('--out'), size = Number(arg('--size'));
    const source = await readFile(state.executable), image = Buffer.alloc(size);
    source.copy(image, 0, 0, Math.min(source.length, image.length));
    const pe = source.readUInt32LE(60), optional = pe + 24;
    const header = {machine: source.readUInt16LE(pe + 4), optional_magic: source.readUInt16LE(optional),
      number_of_sections: source.readUInt16LE(pe + 6), time_date_stamp: source.readUInt32LE(pe + 8), pe_offset: pe,
      header_extent: optional + source.readUInt16LE(pe + 20) + source.readUInt16LE(pe + 6) * 40,
      size_of_headers: source.readUInt32LE(optional + 60), size_of_image: size,
      entry_point_rva: source.readUInt32LE(optional + 16), preferred_image_base: source.readUInt32LE(optional + 28)};
    const complete = mode !== 'partial', observed = complete ? size : size / 2;
    if (!complete) image.fill(0, observed);
    const accepted = image.subarray(0, observed), start = identity(), end = identity();
    if (mode === 'wrong-filetime') end.creation_filetime = (BigInt(end.creation_filetime) + 1n).toString();
    const helperFile = args.find(value => value.endsWith('memory-image.py'));
    const helperBytes = await readFile(helperFile);
    const result = {schema_version: 1, status: complete ? 'completed' : 'partial', pid: state.pid,
      base: '0x400000', size_bytes: size, atomic: false, runnable_pe: false, layout: 'flat_rva_memory',
      observation: 'cooperative_non_atomic_external_read', unobserved_fill: 'zero', zero_fill_is_observed: false,
      started_utc: started, ended_utc: now(), elapsed_ms: 1,
      limits: {image_bytes: 67108864, chunk_bytes: 65536, retry_page_bytes: 4096, timeout_ms: 10000},
      identity: {expected_executable: state.executable, expected_creation_filetime: state.creation_filetime, start, end},
      source: {path: state.executable, size_bytes: source.length, sha256: digest(source), header,
        verified_stable: true, write_delete_sharing_denied: true}, live_header: header, mutable_header_differences: [],
      coverage: {observed_bytes: observed, unobserved_bytes: size - observed, unverified_output_bytes: 0,
        coverage_complete: complete, counting: 'union_of_observed_prefix_bytes_per_disjoint_rva_extent',
        pages: [{rva: '0x0', requested_bytes: size, observed_bytes: observed, observed_prefix_bytes: observed,
          coverage_complete: complete, observed_sha256: digest(accepted), attempts: [{rva: '0x0', requested_bytes: size,
            success: complete, winerror: complete ? 0 : 299, transferred_bytes: observed, source: 'initial_chunk',
            transferred_sha256: digest(accepted), output_write: {success: true, written_prefix_bytes: observed}}]}]},
      image: {file: path.basename(prefix) + '.bin', size_bytes: size, sha256: digest(image), hash_includes_unobserved_zero_fill: true},
      tool: {file: 'memory-image.py', size_bytes: helperBytes.length, sha256: digest(helperBytes)},
      cleanup: {process_handle_closed: true, source_handle_closed: true},
      error: complete ? null : {code: 'PARTIAL_CAPTURE', message: 'Synthetic unknown byte gap'}};
    await writeFile(prefix + '.bin', image, {flag: 'wx'});
    await writeFile(prefix + '.json', JSON.stringify(result) + '\n', {encoding: 'utf8', flag: 'wx'});
    process.stdout.write(JSON.stringify(result) + '\n', 'utf8');
  }
} else if (role === 'windows') {
  const token = BigInt(state.creation_filetime) + (mode === 'wrong-window-filetime' ? 1n : 0n);
  const milliseconds = Number((token - 116444736000000000n) / 10000n);
  const whole = new Date(milliseconds).toISOString().slice(0, 19);
  const fraction = (token % 10000000n).toString().padStart(7, '0');
  const window = {handle: '0x123', parent_handle: null, thread_id: 1, process_id: state.pid,
    class_name: 'Synthetic', text: 'No window API was called', visible: false, text_query_timed_out: false,
    text_query_status: 'caption', text_query_error_code: null, text_at_buffer_limit: false};
  const result = {schema_version: 1, kind: 'path_bound_window_inventory', pid: state.pid, executable: state.executable,
    process_started_at: whole + '.' + fraction + 'Z', observed_at: now(),
    scope: 'window metadata and bounded WM_GETTEXT only; no clicks or input',
    inventory: {windows: mode === 'bad-window-inventory' ? Array.from({length: 257}, (_, i) => ({...window, handle: '0x' + (i + 1).toString(16)})) : [], truncated: false}};
  await writeFile(arg('-OutputFile'), JSON.stringify(result) + '\n', {encoding: 'utf8', flag: 'wx'});
  process.stdout.write(JSON.stringify(result) + '\n', 'utf8');
} else throw new Error('Unexpected synthetic observer role: ' + role);
