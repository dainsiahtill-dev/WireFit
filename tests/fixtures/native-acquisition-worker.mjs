// Synthetic protocol producer. It never spawns or executes the staged PE.
import {readFileSync} from 'node:fs';
import {readFile, writeFile, rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';

const [repository, stateFile] = process.argv.slice(2);
const request = JSON.parse(readFileSync(0, 'utf8'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const identities = {};
for (const [role, name, source] of [
  ['worker', 'trace-worker.py', 'worker.py'], ['agent', 'trace-agent.js', 'agent.js'],
]) {
  const bytes = await readFile(path.join(repository, 'tools/native-trace', source));
  await writeFile(name, bytes, {flag: 'wx'});
  identities[role] = {file: name, size_bytes: bytes.length, sha256: digest(bytes)};
}
identities.frida = {version: 'synthetic-no-frida', module_path: process.execPath};
const creation = (116444736000000000n + BigInt(Date.now()) * 10000n + 1234n).toString();
const state = {synthetic: true, target_execution: 'not_run', pid: process.pid,
  executable: request.target, creation_filetime: creation, work: process.cwd()};
const ready = {type: 'agent_ready', frida_version: 'synthetic-no-frida', arch: 'ia32', pointer_size: 4,
  image_base: '0x400000', image_size: 8192, initial_threads: 1, hardware_breakpoints: 0, installed_api_hooks: 0};
const result = {schema_version: 1, status: 'failed', error: {code: 'INTERRUPTED', message: 'Synthetic collection in progress'},
  pid: process.pid, frida_version: 'synthetic-no-frida', identities, events: [ready], snapshots: [],
  omitted_events: 0, omitted_events_complete: false, hook_states: {initial: [], current: [], final: []},
  hook_states_complete: false, is_checkpoint: true, checkpoint_sequence: 1,
  cleanup: {owned_pid_terminated: false, session_detached: false, windows_job_assigned: true, windows_job_closed: false, errors: []},
  synthetic: true, target_execution: 'not_run'};
async function snapshots(phase) {
  for (const [index, range] of request.ranges.entries()) {
    const bytes = Buffer.alloc(range.size_bytes, 0x53), file = `synthetic-${phase}-${index}.bin`;
    await writeFile(file, bytes, {flag: 'wx'});
    result.snapshots.push({...range, phase, file, sha256: digest(bytes)});
  }
}
await snapshots('initial');
await writeFile('trace-checkpoint.tmp.json', JSON.stringify(result) + '\n', {encoding: 'utf8', flag: 'wx'});
await rename('trace-checkpoint.tmp.json', 'trace-checkpoint.json');
await writeFile(stateFile, JSON.stringify(state) + '\n', {encoding: 'utf8', flag: 'wx'});
await new Promise(resolve => setTimeout(resolve, request.duration_ms));
await snapshots('final');
Object.assign(result, {status: 'completed', error: null, omitted_events_complete: true, hook_states_complete: true,
  is_checkpoint: false, checkpoint_sequence: 2,
  cleanup: {owned_pid_terminated: true, session_detached: true, windows_job_assigned: true, windows_job_closed: true, errors: []}});
await writeFile(stateFile + '.finished', 'synthetic worker completed naturally\n', {encoding: 'utf8', flag: 'wx'});
process.stdout.write(JSON.stringify(result) + '\n', 'utf8');
