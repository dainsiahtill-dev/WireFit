import {afterEach, describe, expect, it} from 'vitest';
import {mkdtemp, writeFile, readFile, realpath, lstat, rm, readdir} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {acquireNativeEvidence} from '../src/native-acquisition.js';
import type {AcquisitionOptions} from '../src/native-acquisition-options.js';
import {runProcess} from '../src/process.js';

const repository = path.resolve('.'), roots: string[] = [];
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const load = async (file: string) => JSON.parse(await readFile(file, 'utf8'));
afterEach(async () => {
  for (const root of roots.splice(0)) {
    const resolved = await realpath(root), parent = await realpath(tmpdir());
    expect(path.dirname(resolved).toLowerCase()).toBe(parent.toLowerCase());
    expect(path.basename(resolved).startsWith('wirefit-acquisition-integration-')).toBe(true);
    expect((await lstat(root)).isSymbolicLink()).toBe(false);
    await rm(resolved, {recursive: true, force: true});
  }
});
async function fixture(mode = 'complete') {
  const root = await mkdtemp(path.join(tmpdir(), 'wirefit-acquisition-integration-')); roots.push(root);
  // Valid PE32 metadata is input data only. The configured Node worker never executes it.
  const source = Buffer.alloc(8192); source.write('MZ'); source.writeUInt32LE(128, 60); source.write('PE\0\0', 128);
  source.writeUInt16LE(0x14c, 132); source.writeUInt16LE(1, 134); source.writeUInt16LE(224, 148);
  const o = 152; source.writeUInt16LE(0x10b, o); source.writeUInt32LE(4096, o + 16); source.writeUInt32LE(0x400000, o + 28);
  source.writeUInt32LE(4096, o + 32); source.writeUInt32LE(512, o + 36); source.writeUInt32LE(8192, o + 56);
  source.writeUInt32LE(512, o + 60); source.writeUInt32LE(16, o + 92);
  const section = o + 224; source.write('.text', section); source.writeUInt32LE(512, section + 8);
  source.writeUInt32LE(4096, section + 12); source.writeUInt32LE(512, section + 16); source.writeUInt32LE(512, section + 20);
  source.writeUInt32LE(0x60000020, section + 36); source[512] = 0xc3;
  const file = path.join(root, 'synthetic-never-executed.exe'), config = path.join(root, 'config.json'), planFile = path.join(root, 'plan.json');
  const stateFile = path.join(root, 'synthetic-worker-state.json');
  await writeFile(file, source);
  await writeFile(config, JSON.stringify({command: process.execPath,
    args: [path.join(repository, 'tests/fixtures/native-acquisition-worker.mjs'), repository, stateFile]}) + '\n', 'utf8');
  const plan = {duration_ms: 3000, breakpoints_rva: [], api_hooks: [], max_events: 16, ranges: [{rva: '0x1000', size_bytes: 1}]};
  await writeFile(planFile, JSON.stringify(plan) + '\n', 'utf8');
  const options: AcquisitionOptions = {file, config, plan: planFile, out: path.join(root, 'acquired'), python: process.execPath,
    capture_at_ms: 0, callers: []};
  const calls: {command: string; args: string[]}[] = [];
  const run: typeof runProcess = async (command, args, settings = {}) => {
    calls.push({command, args});
    // Keep both production CLI routes real. Source translation is only for a not-yet-built bridge.
    const cliIndex = args.findIndex(arg => /[\\/]dist[\\/]src[\\/](?:cli|native-acquisition-cli)\.js$/.test(arg));
    if (cliIndex >= 0) {
      const entry = args[cliIndex]!.replace(/[\\/]dist[\\/]src[\\/]/, path.sep + 'src' + path.sep).replace(/\.js$/, '.ts');
      return runProcess(command, ['--import', 'tsx', entry, ...args.slice(cliIndex + 1)], settings);
    }
    const role = args.includes('-c') ? 'identity' : args.includes('--pid') ? 'main' : args.includes('-TargetPid') ? 'windows' : null;
    if (!role) throw new Error('Test refuses replacement of an unexpected command: ' + JSON.stringify(args));
    return runProcess(process.execPath, [path.join(repository, 'tests/fixtures/native-acquisition-observer.mjs'),
      stateFile, role, mode, JSON.stringify(args)], settings);
  };
  return {root, source, options, stateFile, run, calls};
}
async function persisted(receipt: any, out: string) {
  const saved = await load(path.join(out, 'receipt.json'));
  expect(saved.status).toBe(receipt.status);
  expect(saved.runnable_verified).toBe(false);
  return saved;
}

describe('owned acquisition through the actual public CLI with synthetic script observers', () => {
  it('collects one new case with fixed inputs and preserves source bytes without executing the PE', async () => {
    const f = await fixture();
    const receipt: any = await acquireNativeEvidence(f.options, {run: f.run});
    expect(receipt.status, JSON.stringify({error: receipt.error, finalization_errors: receipt.finalization_errors,
      cli_trace: receipt.cli_trace, collectors: receipt.collectors, code_unchanged: receipt.code_unchanged, job: receipt.job}, null, 2)).toBe('observations_collected');
    expect(receipt.job).toMatchObject({operation: 'trace_binary', status: 'completed'});
    expect(receipt.trace.status).toBe('completed');
    expect(receipt.trace_raw.synthetic).toBe(true);
    expect(receipt.trace_raw.target_execution).toBe('not_run');
    expect(receipt.collectors.main.result.observation).toBe('cooperative_non_atomic_external_read');
    expect(receipt.collectors.private.status).toBe('not_requested');
    expect(receipt.collectors.windows.status).toBe('not_requested');
    expect(receipt.finalization_errors).toEqual([]);
    expect(await readFile(f.options.file)).toEqual(f.source);
    expect((await load(f.stateFile)).target_execution).toBe('not_run');
    expect((await readFile(f.stateFile + '.finished', 'utf8'))).toContain('completed naturally');
    expect(f.calls.filter(call => call.args.includes('create'))).toHaveLength(1);
    expect(f.calls.filter(call => call.args.includes('trace'))).toHaveLength(1);
    const traceCall = f.calls.find(call => call.args.includes('trace'))!;
    const frozenConfig = traceCall.args[traceCall.args.indexOf('--config') + 1]!;
    const frozenPlan = traceCall.args[traceCall.args.indexOf('--plan') + 1]!;
    expect(path.dirname(frozenConfig)).not.toBe(f.root);
    expect(path.relative(f.options.out, frozenConfig).startsWith('..')).toBe(false);
    expect(await load(frozenConfig)).toEqual(await load(f.options.config));
    expect(await load(frozenPlan)).toEqual(await load(f.options.plan));
    const saved = await persisted(receipt, f.options.out), before = digest(await readFile(path.join(f.options.out, 'receipt.json')));
    expect(saved.source.unchanged).toBe(true);
    await expect(acquireNativeEvidence(f.options, {run: f.run})).rejects.toMatchObject({code: 'ACQUISITION_PATH_INVALID'});
    expect(digest(await readFile(path.join(f.options.out, 'receipt.json')))).toBe(before);
  }, 25000);

  it.each(['bad-json', 'partial'])('retains %s observer evidence and lets the owned trace finish naturally', async mode => {
    const f = await fixture(mode);
    const receipt: any = await acquireNativeEvidence(f.options, {run: f.run});
    expect(receipt.status).toBe('partial_or_failed');
    expect(receipt.job.status).toBe('completed');
    expect(receipt.trace.status).toBe('completed');
    expect(receipt.collectors.main.status).not.toBe('completed');
    expect(await readFile(f.stateFile + '.finished', 'utf8')).toContain('completed naturally');
    expect(await readFile(f.options.file)).toEqual(f.source);
    const names = await readdir(f.options.out);
    const mainOutput = names.filter(name => /main.*stdout/.test(name));
    expect(mainOutput).toHaveLength(1);
    const output = await readFile(path.join(f.options.out, mainOutput[0]!), 'utf8');
    if (mode === 'bad-json') expect(output).toContain('synthetic invalid JSON');
    else expect(JSON.parse(output).coverage).toMatchObject({observed_bytes: 4096, unobserved_bytes: 4096, coverage_complete: false});
    expect((await persisted(receipt, f.options.out)).collectors.main).toBeTruthy();
  }, 25000);

  it('rejects a one-tick creation mismatch and cancels its own CLI job without upgrading evidence', async () => {
    const f = await fixture('wrong-filetime');
    const receipt: any = await acquireNativeEvidence(f.options, {run: f.run});
    expect(receipt.status).not.toBe('observations_collected');
    expect(receipt.job.status).toBe('cancelled');
    expect(receipt.trace.status).toBe('cancelled');
    expect(receipt.collectors.main.status).not.toBe('completed');
    await expect(readFile(f.stateFile + '.finished', 'utf8')).rejects.toMatchObject({code: 'ENOENT'});
    const saved = await persisted(receipt, f.options.out);
    expect(JSON.stringify(saved)).toMatch(/IDENTITY|FILETIME|creation/i);
    expect(saved.trace_raw.cleanup.owned_pid_terminated).toBe(false);
  }, 25000);

  it('retains invalid window metadata without cancelling a correctly identified owned trace', async () => {
    const f = await fixture('bad-window-inventory');
    const receipt: any = await acquireNativeEvidence({...f.options, powershell: process.execPath}, {run: f.run});
    expect(receipt.status).toBe('partial_or_failed');
    expect(receipt.job.status).toBe('completed');
    expect(receipt.collectors.windows.status).toBe('failed');
    expect(await readFile(f.stateFile + '.finished', 'utf8')).toContain('completed naturally');
    expect((await persisted(receipt, f.options.out)).collectors.windows.result.inventory.windows).toHaveLength(257);
  }, 25000);

  it('does not report success when the actual public CLI exits zero with damaged JSON stdout', async () => {
    const f = await fixture();
    const run: typeof runProcess = async (command, args, settings) => {
      const result = await f.run(command, args, settings);
      return args.includes('trace') ? {...result, stdout: 'damaged public CLI JSON\n'} : result;
    };
    const receipt: any = await acquireNativeEvidence(f.options, {run});
    expect(receipt.job.status).toBe('completed');
    expect(receipt.trace.status).toBe('completed');
    expect(receipt.status).toBe('partial_or_failed');
    expect(receipt.cli_trace.status).toBe('failed');
    expect(receipt.cli_trace.error).toMatchObject({code: 'ACQUISITION_JSON_INVALID'});
    expect(await readFile(path.join(f.options.out, 'cli-trace-stdout.txt'), 'utf8')).toBe('damaged public CLI JSON\n');
  }, 25000);

  it('cancels its own job when a window observer reports a creation token one tick away', async () => {
    const f = await fixture('wrong-window-filetime');
    const receipt: any = await acquireNativeEvidence({...f.options, powershell: process.execPath}, {run: f.run});
    expect(receipt.status).toBe('partial_or_failed');
    expect(receipt.job.status).toBe('cancelled');
    expect(receipt.trace.status).toBe('cancelled');
    expect(receipt.collectors.windows.status).toBe('failed');
    expect(receipt.collectors.windows.error).toMatchObject({code: 'ACQUISITION_OWNERSHIP_INVALID'});
    await expect(readFile(f.stateFile + '.finished', 'utf8')).rejects.toMatchObject({code: 'ENOENT'});
    expect((await persisted(receipt, f.options.out)).error).toMatchObject({code: 'ACQUISITION_OWNERSHIP_INVALID'});
  }, 25000);

  it('rejects an existing output and invalid passive plan before starting any child', async () => {
    const f = await fixture();
    await writeFile(f.options.out, 'existing evidence\n', 'utf8');
    await expect(acquireNativeEvidence(f.options, {run: f.run})).rejects.toMatchObject({code: 'ACQUISITION_PATH_INVALID'});
    expect(f.calls).toEqual([]);
    expect(await readFile(f.options.out, 'utf8')).toBe('existing evidence\n');
    await writeFile(f.options.plan, JSON.stringify({duration_ms: 3000, breakpoints_rva: ['0x1000'], api_hooks: [], max_events: 16, ranges: []}), 'utf8');
    await expect(acquireNativeEvidence({...f.options, out: f.options.out + '-invalid'}, {run: f.run})).rejects.not.toMatchObject({code: 'ACQUISITION_NOT_IMPLEMENTED'});
    expect(f.calls).toEqual([]);
    await expect(lstat(f.options.out + '-invalid')).rejects.toMatchObject({code: 'ENOENT'});
  });

  it('uses graceful public CLI cancellation on AbortSignal and retains the cancelled case', async () => {
    const f = await fixture(), controller = new AbortController();
    const task = acquireNativeEvidence(f.options, {run: f.run, signal: controller.signal});
    void task.catch(() => undefined); // Preserve the original rejection until the owned lifecycle is awaited below.
    try {
      const deadline = Date.now() + 12000;
      while (Date.now() < deadline) {
        try { await readFile(f.stateFile, 'utf8'); break; } catch (error: any) { if (error.code !== 'ENOENT') throw error; }
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      expect((await load(f.stateFile)).synthetic).toBe(true);
      controller.abort();
      const receipt: any = await task;
      expect(receipt.status).not.toBe('observations_collected');
      expect(receipt.job.status).toBe('cancelled');
      expect(receipt.trace.status).toBe('cancelled');
      expect(receipt.cli_trace.execution.cancel_mode).toBe('ipc_requested');
      expect((await persisted(receipt, f.options.out)).job.status).toBe('cancelled');
      const workerPid = (await load(f.stateFile)).pid;
      expect(() => process.kill(workerPid, 0)).toThrow(); // A read-only liveness probe; cancellation owns the fixture lifecycle.
    } finally { controller.abort(); await task.catch(() => undefined); }
  }, 25000);
});
