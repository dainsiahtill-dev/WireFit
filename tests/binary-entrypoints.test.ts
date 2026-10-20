import { it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createMcpServer } from '../src/mcp.js';
import { WirefitService } from '../src/service.js';
import { sha256 } from '../src/shared.js';

const root = path.resolve('.');
const local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
const execute = promisify(execFile);
const nativeFixture = path.join(root, 'artifacts/native/fixture-build/wirefit-fixture.exe');

/** A minimal source-owned PE32 containing a single RET; never executed by these tests. */
function pe32(): Buffer {
  const bytes = Buffer.alloc(1024);
  bytes.write('MZ', 0, 'ascii');
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write('PE\0\0', 0x80, 'ascii');
  bytes.writeUInt16LE(0x14c, 0x84);
  bytes.writeUInt16LE(1, 0x86);
  bytes.writeUInt16LE(224, 0x94);
  bytes.writeUInt16LE(0x102, 0x96);
  const optional = 0x98;
  bytes.writeUInt16LE(0x10b, optional);
  bytes.writeUInt32LE(0x200, optional + 4);
  bytes.writeUInt32LE(0x1000, optional + 16);
  bytes.writeUInt32LE(0x1000, optional + 20);
  bytes.writeUInt32LE(0x400000, optional + 28);
  bytes.writeUInt32LE(0x1000, optional + 32);
  bytes.writeUInt32LE(0x200, optional + 36);
  bytes.writeUInt32LE(0x2000, optional + 56);
  bytes.writeUInt32LE(0x200, optional + 60);
  bytes.writeUInt16LE(3, optional + 68);
  bytes.writeUInt32LE(16, optional + 92);
  const section = optional + 224;
  bytes.write('.text', section, 'ascii');
  bytes.writeUInt32LE(1, section + 8);
  bytes.writeUInt32LE(0x1000, section + 12);
  bytes.writeUInt32LE(0x200, section + 16);
  bytes.writeUInt32LE(0x200, section + 20);
  bytes.writeUInt32LE(0x60000020, section + 36);
  bytes[0x200] = 0xc3;
  return bytes;
}

async function cli(...args: string[]) {
  let stdout: string, stderr: string, code = 0;
  try {
    ({ stdout, stderr } = await execute(
      runtime,
      ['--import', 'tsx', path.join(root, 'src/cli.ts'), ...args],
      { cwd: root, encoding: 'utf8', windowsHide: true },
    ));
  } catch (error) {
    const failed = error as Error & { code: number; stdout: string; stderr: string };
    if (typeof failed.code !== 'number' || !failed.stdout) throw error;
    ({ stdout, stderr, code } = failed);
  }
  return { code, data: JSON.parse(stdout) as any, stderr };
}

async function mcp(service: WirefitService) {
  const server = await createMcpServer(service);
  const client = new Client({ name: 'wirefit-binary-test', version: '1.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

it('submits static PE inspection through MCP and preserves its case job and report', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-mcp-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const connection = await mcp(service);
  try {
    const bytes = pe32(), file = path.join(dir, '源 程序.exe');
    await writeFile(file, bytes);
    const submitted = await connection.client.callTool({
      name: 'wirefit_inspect_binary',
      arguments: { file, timeout_ms: 10000 },
    });
    expect(submitted.isError).not.toBe(true);
    const job = await service.jobs.wait((submitted.structuredContent as any).job_id);
    expect(job.status).toBe('completed');
    expect(job.result_id).toMatch(/^[A-Za-z][A-Za-z0-9_.:-]+$/);
    const report = await connection.client.callTool({
      name: 'wirefit_get_report',
      arguments: { result_id: job.result_id },
    });
    expect(report.isError).not.toBe(true);
    const result = (report.structuredContent as any).data;
    expect(result.source.sha256).toBe(sha256(bytes));
    const inspection = JSON.parse((await service.store.readArtifact(result.inspection_artifact)).toString('utf8'));
    expect(inspection).toMatchObject({ format: 'PE32', sha256: sha256(bytes), size_bytes: 1024 });
    expect(result.detector.status).toBe('not_configured');
    expect(result.validation).toMatchObject({ source_unchanged: true, runnable_verified: false });
    expect((await readFile(file)).equals(bytes)).toBe(true);
    const request = await connection.client.callTool({
      name: 'wirefit_get_report',
      arguments: { result_id: job.result_id, section: 'request' },
    });
    expect((request.structuredContent as any).data).toMatchObject({ file, timeout_ms: 10000 });
  } finally {
    await connection.close();
    await service.close();
    await rm(dir, { recursive: true, force: true });
  }
});

it('rejects strict binary MCP fields before scheduling and keeps binary operations outside experiments', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-schema-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const connection = await mcp(service);
  try {
    const { tools } = await connection.client.listTools();
    const inspect = tools.find((tool) => tool.name === 'wirefit_inspect_binary');
    const unpack = tools.find((tool) => tool.name === 'wirefit_unpack_binary');
    expect(inspect).toBeDefined();
    expect(unpack?.annotations).toMatchObject({ readOnlyHint: false, openWorldHint: true });
    expect(inspect?.annotations?.readOnlyHint).toBe(false);
    const canonical = tools.find((tool) => tool.name === 'wirefit_run_experiment')!;
    const contract = JSON.parse(await readFile(path.join(root, 'contracts/experiment-request.schema.json'), 'utf8'));
    expect(canonical.inputSchema.oneOf).toHaveLength(contract.oneOf.length);
    const invalid = [
      ['wirefit_inspect_binary', {}],
      ['wirefit_inspect_binary', { file: 'a.exe', output: 'overwrite.exe' }],
      ['wirefit_inspect_binary', { file: 'a\0.exe' }],
      ['wirefit_inspect_binary', { file: 'a.exe', timeout_ms: 0 }],
      ['wirefit_inspect_binary', { file: 'a.exe', toolchain: { shell: true } }],
      ['wirefit_inspect_binary', { file: 'a.exe', toolchain: { detector: { command: 'tool', env: {} } } }],
      ['wirefit_inspect_binary', { file: 'a.exe', toolchain: { detector: { command: 'tool', args: [1] } } }],
      ['wirefit_unpack_binary', { file: 'a.exe', backend: 'unlicense' }],
      ['wirefit_unpack_binary', { file: 'a.exe', backend: 'auto', toolchain: {} }],
      ['wirefit_unpack_binary', { file: 'a.exe', backend: 'unlicense', toolchain: {}, target_timeout_seconds: 0 }],
      ['wirefit_unpack_binary', { file: 'a.exe', backend: 'unlicense', toolchain: {}, copy_dependencies: 'false' }],
      ['wirefit_unpack_binary', { file: 'a.exe', backend: 'unlicense', toolchain: { unpackers: { unknown: { command: 'tool' } } } }],
      ['wirefit_run_experiment', { operation: 'inspect_binary', file: 'a.exe' }],
    ] as const;
    for (const [name, args] of invalid) {
      const denied = await connection.client.callTool({ name, arguments: args });
      expect(denied.isError, name + JSON.stringify(args)).toBe(true);
      expect((denied.structuredContent as any).error.code).toBe('SCHEMA_INVALID');
    }
    expect(await service.store.listObjects('jobs')).toEqual([]);
  } finally {
    await connection.close();
    await service.close();
    await rm(dir, { recursive: true, force: true });
  }
});

it('runs static binary CLI inspection in the foreground and retains the same durable report', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-cli-'));
  const caseDir = path.join(dir, 'case');
  try {
    const bytes = pe32(), file = path.join(dir, '源 程序.exe');
    await writeFile(file, bytes);
    expect((await cli('case', 'create', '--dir', caseDir)).code).toBe(0);
    const inspected = await cli('binary', 'inspect', '--case', caseDir, '--file', file, '--timeout', '10000');
    expect(inspected.code, JSON.stringify(inspected.data)).toBe(0);
    expect(inspected.data.job.status).toBe('completed');
    expect(inspected.stderr).toContain('job_submitted');
    expect(inspected.stderr).toContain('job_finished');
    expect(inspected.data.result.source.sha256).toBe(sha256(bytes));
    const persisted = await cli('show', '--case', caseDir, '--kind', 'runs', '--id', inspected.data.job.result_id);
    expect(persisted.data.result).toEqual(inspected.data.result);
    expect(persisted.data.request).toMatchObject({ file, timeout_ms: 10000 });
    expect((await readFile(file)).equals(bytes)).toBe(true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 30000);

it.skipIf(!existsSync(nativeFixture))('inspects the actual source-owned compiled Windows PE through the CLI', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-native-'));
  const caseDir = path.join(dir, 'case');
  try {
    const before = sha256(await readFile(nativeFixture));
    expect((await cli('case', 'create', '--dir', caseDir)).code).toBe(0);
    const inspected = await cli('binary', 'inspect', '--case', caseDir, '--file', nativeFixture);
    expect(inspected.code, JSON.stringify(inspected.data)).toBe(0);
    expect(inspected.data.job.status).toBe('completed');
    const metadata = JSON.parse(await readFile(path.join(caseDir, inspected.data.result.inspection_artifact.relative_path), 'utf8'));
    expect(metadata.format).toBe('PE32+');
    expect(inspected.data.result.source.sha256).toBe(before);
    expect(sha256(await readFile(nativeFixture))).toBe(before);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 30000);

it('uses the configured CLI detector and records its failure alongside static metadata', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-cli-detector-'));
  const caseDir = path.join(dir, 'case');
  try {
    const bytes = pe32(), file = path.join(dir, 'source.exe');
    const detector = path.join(dir, 'synthetic-failing-detector.cjs');
    const config = path.join(dir, 'toolchain.json');
    await writeFile(file, bytes);
    await writeFile(
      detector,
      "process.stderr.write('Synthetic detector failure fixture.\\n');process.exit(19);",
      'utf8',
    );
    await writeFile(config, JSON.stringify({ detector: { command: runtime, args: [detector] } }), 'utf8');
    expect((await cli('case', 'create', '--dir', caseDir)).code).toBe(0);
    const inspected = await cli(
      'binary', 'inspect', '--case', caseDir, '--file', file, '--config', config,
    );
    expect(inspected.code, JSON.stringify(inspected.data)).toBe(1);
    expect(inspected.data.job.status).toBe('failed');
    expect(inspected.data.result.detector.status).toBe('failed');
    expect(inspected.data.result.error.code).toBe('DETECTOR_FAILED');
    expect(inspected.data.result.source.sha256).toBe(sha256(bytes));
    expect(inspected.data.result.inspection_artifact).not.toBeNull();
    expect(inspected.data.result.logs.length).toBeGreaterThan(0);
    expect((await readFile(file)).equals(bytes)).toBe(true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 30000);

it('maps explicit binary CLI backend options into a failed auditable job without claiming unpacking', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-cli-failure-'));
  const caseDir = path.join(dir, 'case');
  try {
    const bytes = pe32(), file = path.join(dir, 'source.exe');
    const logger = path.join(dir, 'synthetic-failing-tool.cjs');
    const argvFile = path.join(dir, 'tool argv.json');
    const config = path.join(dir, 'toolchain.json');
    const marker = 'literal ; echo Ω';
    await writeFile(file, bytes);
    await writeFile(logger, "const fs=require('node:fs');fs.writeFileSync(process.argv[2],JSON.stringify(process.argv.slice(3)),'utf8');process.stderr.write('Synthetic failure fixture; no unpacking performed.\\n');process.exit(17);", 'utf8');
    await writeFile(config, JSON.stringify({ unpackers: { unlicense: { command: runtime, args: [logger, argvFile, marker, ''] } } }), 'utf8');
    expect((await cli('case', 'create', '--dir', caseDir)).code).toBe(0);
    const failed = await cli('binary', 'unpack', '--case', caseDir, '--file', file, '--backend', 'unlicense', '--config', config, '--timeout', '10000', '--target-timeout', '7', '--no-copy-dependencies');
    expect(failed.code, JSON.stringify(failed.data)).toBe(1);
    expect(failed.data.job.status).toBe('failed');
    expect(failed.data.result.status).toBe('failed');
    expect(failed.data.result.outputs).toEqual([]);
    expect(failed.data.result.validation).toMatchObject({ source_unchanged: true, runnable_verified: false });
    expect(failed.data.result.error.code).toEqual(expect.any(String));
    expect(failed.data.result.logs.length).toBeGreaterThan(0);
    const recordedArgs = JSON.parse(await readFile(argvFile, 'utf8'));
    expect(recordedArgs[0]).toBe(marker);
    expect(recordedArgs[1]).toBe('');
    const persisted = await cli('show', '--case', caseDir, '--kind', 'runs', '--id', failed.data.job.result_id);
    expect(persisted.data.request).toMatchObject({ file, backend: 'unlicense', timeout_ms: 10000, target_timeout_seconds: 7, copy_dependencies: false });
    expect((await readFile(file)).equals(bytes)).toBe(true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 30000);

it('rejects binary CLI syntax and malformed toolchains before creating jobs', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-cli-invalid-'));
  const caseDir = path.join(dir, 'case');
  try {
    expect((await cli('case', 'create', '--dir', caseDir)).code).toBe(0);
    const config = path.join(dir, 'toolchain.json');
    await writeFile(config, '{}', 'utf8');
    const invalidArgs = [
      ['binary', 'inspect', '--file', 'a.exe'],
      ['binary', 'inspect', '--case', caseDir],
      ['binary', 'inspect', '--case', caseDir, '--file', 'a.exe', '--timeout', '0'],
      ['binary', 'inspect', '--case', caseDir, '--file', 'a.exe', '--timeout', '600001'],
      ['binary', 'inspect', '--case', caseDir, '--file', 'a.exe', '--no-copy-dependencies'],
      ['binary', 'unpack', '--case', caseDir, '--file', 'a.exe', '--config', config],
      ['binary', 'unpack', '--case', caseDir, '--file', 'a.exe', '--backend', 'unlicense'],
      ['binary', 'unpack', '--case', caseDir, '--file', 'a.exe', '--backend', 'auto', '--config', config],
      ['binary', 'unpack', '--case', caseDir, '--file', 'a.exe', '--backend', 'unlicense', '--config', config, '--target-timeout', '601'],
      ['binary', 'unpack', '--case', caseDir, '--file', 'a.exe', '--backend', 'unlicense', '--config', config, '--no-copy-dependencies=false'],
    ];
    for (const args of invalidArgs) {
      const denied = await cli(...args);
      expect(denied.code, args.join(' ')).toBe(2);
      expect(denied.data.error.code).toBe('CLI_USAGE');
    }
    for (const invalidConfig of [null, [], { detector: { command: 42 } }, { detector: { command: 'tool', args: [1] } }, { detector: { command: 'tool', shell: true } }, { unpackers: { other: { command: 'tool' } } }]) {
      await writeFile(config, JSON.stringify(invalidConfig), 'utf8');
      const denied = await cli('binary', 'inspect', '--case', caseDir, '--file', 'a.exe', '--config', config);
      expect(denied.code, JSON.stringify(invalidConfig)).toBe(2);
      expect(denied.data.error.code).toBe('CLI_USAGE');
    }
    expect((await cli('jobs', '--case', caseDir)).data.jobs).toEqual([]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 30000);

it('submits the explicit MCP unpack backend and exposes failure through existing job and report tools', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-mcp-failure-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const connection = await mcp(service);
  try {
    const bytes = pe32(), file = path.join(dir, 'source.exe');
    const tool = path.join(dir, 'synthetic-failing-tool.cjs');
    await writeFile(file, bytes);
    await writeFile(tool, "process.stderr.write('Synthetic failure fixture; no unpacking performed.\\n');process.exit(17);", 'utf8');
    const submitted = await connection.client.callTool({
      name: 'wirefit_unpack_binary',
      arguments: { file, backend: 'unlicense', toolchain: { unpackers: { unlicense: { command: runtime, args: [tool] } } }, timeout_ms: 10000, target_timeout_seconds: 7, copy_dependencies: false },
    });
    expect(submitted.isError).not.toBe(true);
    const id = (submitted.structuredContent as any).job_id;
    await service.jobs.wait(id);
    const final = await connection.client.callTool({ name: 'wirefit_get_job', arguments: { job_id: id } });
    const job = final.structuredContent as any;
    expect(job.status).toBe('failed');
    const report = await connection.client.callTool({ name: 'wirefit_get_report', arguments: { result_id: job.result_id } });
    expect(report.isError).not.toBe(true);
    expect((report.structuredContent as any).data).toMatchObject({ status: 'failed', backend: 'unlicense', validation: { source_unchanged: true, runnable_verified: false }, outputs: [] });
    expect((await readFile(file)).equals(bytes)).toBe(true);
  } finally {
    await connection.close();
    await service.close();
    await rm(dir, { recursive: true, force: true });
  }
});

it('cancels the binary MCP job through the existing tool and retains the cancelled run after cleanup', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-binary-mcp-cancel-'));
  const service = await WirefitService.create(path.join(dir, 'case'));
  const connection = await mcp(service);
  try {
    const bytes = pe32(), file = path.join(dir, 'source.exe');
    const tool = path.join(dir, 'synthetic-waiting-tool.cjs');
    const ready = path.join(dir, 'fixture-ready.txt');
    await writeFile(file, bytes);
    await writeFile(
      tool,
      "const fs=require('node:fs');fs.writeFileSync(process.argv[2],'ready','utf8');setInterval(()=>{},1000);",
      'utf8',
    );
    const submitted = await connection.client.callTool({
      name: 'wirefit_unpack_binary',
      arguments: {
        file,
        backend: 'unlicense',
        toolchain: { unpackers: { unlicense: { command: runtime, args: [tool, ready] } } },
        timeout_ms: 10000,
        copy_dependencies: false,
      },
    });
    expect(submitted.isError).not.toBe(true);
    const jobId = (submitted.structuredContent as any).job_id;
    const deadline = Date.now() + 10000;
    while (!existsSync(ready) && Date.now() < deadline)
      await new Promise((resolve) => setTimeout(resolve, 25));
    expect(await readFile(ready, 'utf8')).toBe('ready');
    const cancelled = await connection.client.callTool({
      name: 'wirefit_cancel_job',
      arguments: { job_id: jobId },
    });
    expect(cancelled.isError).not.toBe(true);
    await service.jobs.wait(jobId);
    const final = await connection.client.callTool({
      name: 'wirefit_get_job',
      arguments: { job_id: jobId },
    });
    const job = final.structuredContent as any;
    expect(job.status).toBe('cancelled');
    const report = await connection.client.callTool({
      name: 'wirefit_get_report',
      arguments: { result_id: job.result_id },
    });
    expect(report.isError).not.toBe(true);
    expect((report.structuredContent as any).data).toMatchObject({
      status: 'cancelled',
      outputs: [],
      validation: { source_unchanged: true, runnable_verified: false },
    });
    expect((await readFile(file)).equals(bytes)).toBe(true);
  } finally {
    await connection.close();
    await service.close();
    await rm(dir, { recursive: true, force: true });
  }
}, 30000);
