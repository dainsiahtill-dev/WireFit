import { it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { WirefitService } from '../src/service.js';
import { createMcpServer } from '../src/mcp.js';

const root = path.resolve('.');
const local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
const execute = promisify(execFile);
const plan = {
  duration_ms: 100,
  breakpoints_rva: ['0x1000'],
  ranges: [{ rva: '0x1000', size_bytes: 16 }],
  api_hooks: [{ module: 'kernel32.dll', symbol: 'ExitProcess' }],
  max_events: 16,
};

async function removeOwned(directory: string): Promise<void> {
  const resolved = await realpath(directory), temporaryRoot = await realpath(tmpdir());
  if (path.dirname(resolved) !== temporaryRoot || !path.basename(resolved).startsWith('wirefit-trace-') || (await lstat(directory)).isSymbolicLink())
    throw new Error('Refusing cleanup outside an owned trace test directory');
  await rm(resolved, { recursive: true, force: true });
}

async function connection(service: WirefitService) {
  const server = await createMcpServer(service);
  const client = new Client({ name: 'wirefit-native-trace-test', version: '1.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

async function cli(...args: string[]) {
  try {
    const result = await execute(runtime, ['--import', 'tsx', path.join(root, 'src/cli.ts'), ...args],
      { cwd: root, encoding: 'utf8', windowsHide: true });
    return { code: 0, data: JSON.parse(result.stdout), stderr: result.stderr };
  } catch (error) {
    const result = error as Error & { code: number; stdout: string; stderr: string };
    if (typeof result.code !== 'number' || !result.stdout) throw error;
    return { code: result.code, data: JSON.parse(result.stdout), stderr: result.stderr };
  }
}

// Catches missing public routing and accidental exposure as a mathematical experiment.
it('advertises explicit bounded trace plans with execution annotations and no canonical-union extension', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-schema-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const linked = await connection(service);
  try {
    const { tools } = await linked.client.listTools();
    const trace = tools.find(tool => tool.name === 'wirefit_trace_binary');
    expect(trace).toBeDefined();
    expect(tools).toHaveLength(19);
    const rangeSchema = (trace!.inputSchema.properties as any).plan.properties.ranges.items;
    expect(rangeSchema.required).toEqual(['rva', 'size_bytes']);
    expect(rangeSchema.properties.module).toMatchObject({ type: 'string', not: { enum: ['.', '..'] } });
    expect(trace?.annotations).toMatchObject({ readOnlyHint: false, openWorldHint: true, idempotentHint: false });
    expect(trace?.inputSchema).toMatchObject({ additionalProperties: false, required: ['file', 'tool', 'plan'] });
    const canonical = tools.find(tool => tool.name === 'wirefit_run_experiment')!;
    expect(JSON.stringify(canonical.inputSchema)).not.toContain('trace_binary');
  } finally { await linked.close(); await service.close(); await removeOwned(dir); }
});

// Catches accepting injected manifests/attach targets or deferring invalid input until after scheduling.
it('rejects unknown and over-budget MCP trace fields before any durable job exists', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-invalid-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const linked = await connection(service);
  const request = { file: path.join(dir, 'never-executed.exe'), tool: { command: runtime, args: [] }, plan };
  try {
    const invalid = [
      { ...request, pid: 42 },
      { ...request, manifest: { verdict: 'verified' } },
      { ...request, tool: { command: runtime, shell: true } },
      { ...request, tool: { command: runtime, env: {} } },
      { ...request, tool: { command: runtime, args: [1] } },
      { ...request, plan: { ...plan, verdict: 'equivalent' } },
      { ...request, plan: { ...plan, attach_pid: 42 } },
      { ...request, plan: { ...plan, duration_ms: 0 } },
      { ...request, plan: { ...plan, duration_ms: 60001 } },
      { ...request, plan: { ...plan, max_events: 513 } },
      { ...request, plan: { ...plan, breakpoints_rva: Array(5).fill('0x1000') } },
      { ...request, plan: { ...plan, breakpoints_rva: ['0x100000000'] } },
      { ...request, plan: { ...plan, ranges: [{ rva: '0x1000', size_bytes: 1048577 }] } },
      { ...request, plan: { ...plan, ranges: Array(9).fill({ rva: '0x1000', size_bytes: 1 }) } },
      ...['.', '..', '../kernel32.dll', 'C:\\Windows\\kernel32.dll', 'kernel32.dll:stream', 'x'.repeat(129), 'x\0.dll'].map(module => ({
        ...request, plan: { ...plan, ranges: [{ rva: '0x1000', size_bytes: 4, module }] },
      })),
      { ...request, plan: { ...plan, ranges: [{ rva: '0x1000', size_bytes: 4, module: 'kernel32.dll', module_base: '0x75000000' }] } },
      { ...request, plan: { ...plan, api_hooks: Array(17).fill({ module: 'x.dll', symbol: 'X' }) } },
      { ...request, plan: { ...plan, api_hooks: [{ module: '../ntdll.dll', symbol: 'NtProtectVirtualMemory' }] } },
      { ...request, plan: { ...plan, api_hooks: [{ module: '.', symbol: 'X' }] } },
      { ...request, plan: { ...plan, api_hooks: [{ module: '..', symbol: 'X' }] } },
      { ...request, plan: { ...plan, api_hooks: [{ module: 'x'.repeat(129), symbol: 'X' }] } },
      { ...request, plan: { ...plan, api_hooks: [{ module: 'x.dll', symbol: '-X' }] } },
      { ...request, plan: { ...plan, api_hooks: [{ module: 'x.dll', symbol: 'X'.repeat(257) }] } },
    ];
    for (const input of invalid) {
      const result = await linked.client.callTool({ name: 'wirefit_trace_binary', arguments: input });
      expect(result.isError).toBe(true);
      expect((result.structuredContent as any).error.code).toBe('SCHEMA_INVALID');
    }
    expect(await service.store.listObjects('jobs')).toHaveLength(0);
  } finally { await linked.close(); await service.close(); await removeOwned(dir); }
});

// Catches silently applying defaults or accepting a binary-toolchain config instead of explicit trace-tool config.
it('routes binary trace CLI and rejects missing or injected plan/config fields before scheduling', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-cli-'));
  const caseDir = path.join(dir, 'case');
  const service = await WirefitService.create(caseDir);
  await service.close();
  const config = path.join(dir, 'tool.json'), planFile = path.join(dir, 'plan.json');
  try {
    const missing = await cli('binary', 'trace', '--case', caseDir, '--file', 'not-run.exe');
    expect(missing.code).toBe(2);
    expect(missing.data.error.message).toContain('--config');
    await writeFile(config, JSON.stringify({ command: runtime, args: [], shell: true }), 'utf8');
    await writeFile(planFile, JSON.stringify(plan), 'utf8');
    const injectedConfig = await cli('binary', 'trace', '--case', caseDir, '--file', 'not-run.exe', '--config', config, '--plan', planFile);
    expect(injectedConfig.code).not.toBe(0);
    expect(injectedConfig.data.error.message).not.toContain('Unknown command');
    await writeFile(config, JSON.stringify({ command: runtime, args: [] }), 'utf8');
    await writeFile(planFile, JSON.stringify({ ...plan, manifest: { verdict: 'verified' } }), 'utf8');
    const injectedPlan = await cli('binary', 'trace', '--case', caseDir, '--file', 'not-run.exe', '--config', config, '--plan', planFile);
    expect(injectedPlan.code).not.toBe(0);
    expect(injectedPlan.data.error.message).not.toContain('Unknown command');
    for (const module of ['../kernel32.dll', 'C:\\Windows\\kernel32.dll', '..']) {
      await writeFile(planFile, JSON.stringify({ ...plan, ranges: [{ rva: '0x1000', size_bytes: 4, module }] }), 'utf8');
      const injectedModule = await cli('binary', 'trace', '--case', caseDir, '--file', 'not-run.exe', '--config', config, '--plan', planFile);
      expect(injectedModule.code).not.toBe(0);
      expect(injectedModule.code).toBe(2);
      expect(injectedModule.data.error.code).toBe('CLI_USAGE');
    }
    const reopened = await WirefitService.open(caseDir);
    try { expect(await reopened.store.listObjects('jobs')).toHaveLength(0); } finally { await reopened.close(); }
  } finally { await removeOwned(dir); }
}, 30000);

/** Minimal source-owned PE bytes; every worker below is synthetic Node code, not a PE launcher. */
function pe32(): Buffer {
  const bytes = Buffer.alloc(1024);
  bytes.write('MZ', 0, 'ascii'); bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write('PE\0\0', 0x80, 'ascii'); bytes.writeUInt16LE(0x14c, 0x84);
  bytes.writeUInt16LE(1, 0x86); bytes.writeUInt16LE(224, 0x94); bytes.writeUInt16LE(0x102, 0x96);
  const optional = 0x98;
  bytes.writeUInt16LE(0x10b, optional); bytes.writeUInt32LE(0x1000, optional + 16);
  bytes.writeUInt32LE(0x400000, optional + 28); bytes.writeUInt32LE(0x1000, optional + 32);
  bytes.writeUInt32LE(0x200, optional + 36); bytes.writeUInt32LE(0x2000, optional + 56);
  bytes.writeUInt32LE(0x200, optional + 60); bytes.writeUInt16LE(3, optional + 68);
  bytes.writeUInt32LE(16, optional + 92);
  const section = optional + 224;
  bytes.write('.text', section, 'ascii'); bytes.writeUInt32LE(0x200, section + 8);
  bytes.writeUInt32LE(0x1000, section + 12); bytes.writeUInt32LE(0x200, section + 16);
  bytes.writeUInt32LE(0x200, section + 20); bytes.writeUInt32LE(0x60000020, section + 36);
  bytes[0x200] = 0xc3;
  return bytes;
}

const syntheticWorker = `
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
let input = ''; process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const request = JSON.parse(input);
  const snapshots = [];
  for (const [index, range] of request.ranges.entries()) {
    const scoped = range.module === undefined ? {} : {module:range.module,module_base:null,module_size:null,address:null};
    snapshots.push({...range,...scoped,phase:'initial',error:'synthetic initial memory unavailable'});
    const memory = Buffer.alloc(range.size_bytes, 0x90);
    const file = 'capture-'+String(index).padStart(4,'0')+'.bin';
    fs.writeFileSync(path.join(path.dirname(request.target),file),memory,{flag:'wx'});
    const resolved = range.module === undefined ? {} : {module:range.module,module_base:'0x75e20000',module_size:0xf0000,address:'0x'+(0x75e20000n+BigInt(range.rva)).toString(16)};
    snapshots.push({...range,...resolved,file,phase:'final',sha256:crypto.createHash('sha256').update(memory).digest('hex')});
  }
  const identities = {};
  for(const [role,file] of [['worker','trace-worker.py'],['agent','trace-agent.js']]) {
    const bytes = Buffer.from('synthetic '+role+' source; no target execution','utf8');
    fs.writeFileSync(file,bytes,{flag:'wx'});
    identities[role]={file,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),size_bytes:bytes.length};
  }
  identities.frida={version:'synthetic-no-frida',module_path:process.execPath};
  const states=request.api_hooks.map(api=>({...api,status:'unobserved',observations:0,address:null,error:null}));
  process.stderr.write('synthetic protocol fixture; no target execution\\n');
  process.stdout.write(JSON.stringify({
    schema_version: 1, status: 'completed', frida_version: 'synthetic-no-frida', pid: process.pid,
    identities,hook_states:{initial:states,current:states,final:states},hook_states_complete:true,
    events: [{kind: 'synthetic-protocol', request}], omitted_events: 0, omitted_events_complete:true,
    snapshots,
    cleanup: {owned_pid_terminated: true, session_detached: true,windows_job_assigned:true,windows_job_closed:true}, error: null,
  }) + '\\n');
});
`;

// Catches dropped plan fields, accidental original-path execution, or promotion of memory into a runnable output.
it('runs binary trace CLI in the foreground with a synthetic worker and retains independent trace artifacts', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-cli-protocol-'));
  const caseDir = path.join(dir, 'case');
  const service = await WirefitService.create(caseDir); await service.close();
  const file = path.join(dir, '源 文件.exe'), worker = path.join(dir, 'synthetic.cjs');
  const config = path.join(dir, 'tool.json'), planFile = path.join(dir, 'plan.json');
  const source = pe32();
  try {
    await writeFile(file, source);
    await writeFile(worker, syntheticWorker, 'utf8');
    await writeFile(config, JSON.stringify({ command: runtime, args: [worker] }), 'utf8');
    await writeFile(planFile, JSON.stringify(plan), 'utf8');
    const response = await cli('binary', 'trace', '--case', caseDir, '--file', file, '--config', config, '--plan', planFile);
    expect(response.code).toBe(0);
    expect(response.data.job).toMatchObject({ operation: 'trace_binary', status: 'completed' });
    expect(response.data.result).toMatchObject({
      operation: 'trace_binary', status: 'completed', outputs: [],
      validation: { source_unchanged: true, runnable_verified: false },
    });
    const reopened = await WirefitService.open(caseDir);
    try {
      const result = response.data.result;
      const trace = JSON.parse((await reopened.store.readArtifact(result.trace_artifact)).toString('utf8'));
      expect(trace.frida_version).toBe('synthetic-no-frida');
      expect(trace.events[0].request).toMatchObject({ schema_version: 1, ...plan });
      expect(trace.events[0].request.target).not.toBe(file);
      expect(path.isAbsolute(trace.events[0].request.target)).toBe(true);
      expect(result.snapshots).toHaveLength(1);
      expect(await reopened.store.readArtifact(result.snapshots[0].artifact)).toEqual(Buffer.alloc(16, 0x90));
    } finally { await reopened.close(); }
    expect((await readFile(file)).equals(source)).toBe(true);
  } finally { await removeOwned(dir); }
}, 30000);

// Catches failing to register asynchronous execution with the shared job/report/cancellation lifecycle.
it('submits and cancels an owned MCP trace job and exposes its terminal retained report', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-mcp-cancel-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const linked = await connection(service);
  const file = path.join(dir, 'never-run.exe'), worker = path.join(dir, 'waiting.cjs');
  const ready = path.join(dir, 'worker-ready.txt');
  try {
    await writeFile(file, pe32());
    await writeFile(worker, `const fs=require('node:fs');process.stdin.resume();process.stdin.on('end',()=>{fs.writeFileSync(process.argv[2],'ready','utf8');setInterval(()=>{},1000);});`, 'utf8');
    const submitted = await linked.client.callTool({ name: 'wirefit_trace_binary', arguments: {
      file, tool: { command: runtime, args: [worker, ready] }, plan: { ...plan, duration_ms: 60000 },
    } });
    expect(submitted.isError).not.toBe(true);
    const jobId = (submitted.structuredContent as any).job_id;
    expect(jobId).toBeTypeOf('string');
    const deadline = Date.now() + 10000;
    while (!existsSync(ready) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 25));
    expect(existsSync(ready)).toBe(true);
    const cancelled = await linked.client.callTool({ name: 'wirefit_cancel_job', arguments: { job_id: jobId } });
    expect(cancelled.isError).not.toBe(true);
    await service.jobs.wait(jobId);
    const final = await linked.client.callTool({ name: 'wirefit_get_job', arguments: { job_id: jobId } });
    const job = final.structuredContent as any;
    expect(job).toMatchObject({ operation: 'trace_binary', status: 'cancelled' });
    expect(job.result_id).toBeTypeOf('string');
    const report = await linked.client.callTool({ name: 'wirefit_get_report', arguments: { result_id: job.result_id } });
    expect(report.isError).not.toBe(true);
    const result = (report.structuredContent as any).data;
    expect(result).toMatchObject({ operation: 'trace_binary', status: 'cancelled', outputs: [], validation: { source_unchanged: true, runnable_verified: false } });
    expect(result.logs.length).toBeGreaterThan(0);
  } finally { await linked.close(); await service.close(); await removeOwned(dir); }
}, 30000);






const scopedPlan = {
  ...plan,
  breakpoints_rva: [],
  api_hooks: [],
  ranges: [...plan.ranges, { module: 'kernel32.dll', rva: '0x817fc', size_bytes: 4 }],
};

// A module range can exceed the synthetic main image, and must retain the explicit module scope.
it('passes module-relative ranges through the foreground CLI and preserves resolved snapshot addresses', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-cli-scoped-'));
  const caseDir = path.join(dir, 'case');
  const service = await WirefitService.create(caseDir); await service.close();
  const file = path.join(dir, 'synthetic.exe'), worker = path.join(dir, 'synthetic.cjs');
  const config = path.join(dir, 'tool.json'), planFile = path.join(dir, 'plan.json');
  try {
    await writeFile(file, pe32());
    await writeFile(worker, syntheticWorker, 'utf8');
    await writeFile(config, JSON.stringify({ command: runtime, args: [worker] }), 'utf8');
    await writeFile(planFile, JSON.stringify(scopedPlan), 'utf8');
    const response = await cli('binary', 'trace', '--case', caseDir, '--file', file, '--config', config, '--plan', planFile);
    expect(response.code).toBe(0);
    expect(response.data.job.status).toBe('completed');
    expect(response.data.result.snapshots).toHaveLength(2);
    expect(response.data.result.snapshots[1]).toMatchObject({
      module: 'kernel32.dll', rva: '0x817fc', size_bytes: 4,
      module_base: '0x75e20000', module_size: 0xf0000, address: '0x75ea17fc',
    });
    const reopened = await WirefitService.open(caseDir);
    try {
      const raw = JSON.parse((await reopened.store.readArtifact(response.data.result.trace_artifact)).toString('utf8'));
      expect(raw.events[0].request.ranges).toEqual(scopedPlan.ranges);
      expect(raw.snapshots.find((row: any) => row.module && row.phase === 'initial')).toMatchObject({
        module: 'kernel32.dll', module_base: null, module_size: null, address: null,
        error: 'synthetic initial memory unavailable',
      });
      const run = await reopened.store.getObject<any>('runs', response.data.result.result_id);
      expect(run.request.plan.ranges).toEqual(scopedPlan.ranges);
    } finally { await reopened.close(); }
  } finally { await removeOwned(dir); }
}, 30000);

// Uses the actual MCP handler, job host, protocol validation and case persistence; no Frida/PE execution.
it('accepts a module-relative MCP trace plan and returns module metadata through its retained report', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-trace-mcp-scoped-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const linked = await connection(service);
  const file = path.join(dir, 'synthetic.exe'), worker = path.join(dir, 'synthetic.cjs');
  try {
    await writeFile(file, pe32()); await writeFile(worker, syntheticWorker, 'utf8');
    const submitted = await linked.client.callTool({ name: 'wirefit_trace_binary', arguments: {
      file, tool: { command: runtime, args: [worker] }, plan: scopedPlan,
    } });
    expect(submitted.isError).not.toBe(true);
    const job = await service.jobs.wait((submitted.structuredContent as any).job_id);
    expect(job.status).toBe('completed');
    const response = await linked.client.callTool({ name: 'wirefit_get_report', arguments: { result_id: job.result_id! } });
    expect(response.isError).not.toBe(true);
    const result = (response.structuredContent as any).data;
    expect(result).toMatchObject({ operation: 'trace_binary', status: 'completed', outputs: [], validation: { runnable_verified: false } });
    expect(result.snapshots[1]).toMatchObject({ module: 'kernel32.dll', module_base: '0x75e20000', module_size: 0xf0000, address: '0x75ea17fc' });
    expect(await service.store.readArtifact(result.snapshots[1].artifact)).toEqual(Buffer.alloc(4, 0x90));
    const run = await service.store.getObject<any>('runs', job.result_id!);
    expect(run.request.plan.ranges).toEqual(scopedPlan.ranges);
  } finally { await linked.close(); await service.close(); await removeOwned(dir); }
}, 30000);
