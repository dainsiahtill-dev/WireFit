import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import path from 'node:path';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { ReadBuffer, serializeMessage } from '@modelcontextprotocol/sdk/shared/stdio.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { environment } from '../binary-files.js';
import { assert, errorRecord, WirefitError } from '../shared.js';
import type { WirefitService } from '../service.js';
import type { IdaConfiguration, IdaAnalysisResult } from './types.js';

const MESSAGE_LIMIT = 4 * 1024 * 1024,
  SESSION_LIMIT = 32 * 1024 * 1024;
/** Direct spawn deliberately avoids a supervisor or PID-only ownership decisions. */
class OwnedTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  private child?: ChildProcessWithoutNullStreams;
  private buffer = new ReadBuffer({ maxBufferSize: MESSAGE_LIMIT });
  private ended: Promise<void> = Promise.resolve();
  private closing?: Promise<void>;
  private stdoutBytes = 0;
  private stderrChunks: Buffer[] = [];
  private stderrBytes = 0;
  private stdoutChunks: Buffer[] = [];
  private stdoutStored = 0;
  private diagnostic: unknown = null;
  stderrTruncated = false;
  forced = false;
  closed = false;
  pid: number | null = null;
  constructor(
    private configuration: IdaConfiguration,
    private args: string[],
    private cwd: string,
  ) {}
  async start(): Promise<void> {
    assert(!this.child, 'IDA_TRANSPORT_STATE', 'Owned transport already started');
    const child = spawn(this.configuration.command, this.args, {
      cwd: this.cwd,
      env: { ...environment(), ...this.configuration.env },
      shell: false,
      windowsHide: true,
      detached: process.platform !== 'win32',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child = child;
    this.pid = child.pid ?? null;
    this.ended = new Promise((resolve) =>
      child.once('close', () => {
        this.closed = true;
        resolve();
        this.onclose?.();
      }),
    );
    child.stdout.on('data', (chunk: Buffer) => {
      try {
        this.stdoutBytes += chunk.length;
        const remaining = SESSION_LIMIT - this.stdoutStored;
        if (remaining > 0) {
          const copy = Buffer.from(chunk.subarray(0, remaining));
          this.stdoutChunks.push(copy);
          this.stdoutStored += copy.length;
        }
        assert(this.stdoutBytes <= SESSION_LIMIT, 'IDA_REPLY_BUDGET', 'MCP session stdout exceeded 32 MiB');
        this.buffer.append(chunk);
        let message: JSONRPCMessage | null;
        while ((message = this.buffer.readMessage()) !== null) this.onmessage?.(message);
      } catch (error) {
        this.diagnostic = errorRecord(error, 'ida-transport');
        this.onerror?.(error as Error);
        this.force();
      }
    });
    child.stdout.on('error', (error) => this.onerror?.(error));
    child.stdin.on('error', (error) => this.onerror?.(error));
    child.stderr.on('data', (chunk: Buffer) => {
      const remaining = 1024 * 1024 - this.stderrBytes;
      if (remaining > 0) {
        this.stderrChunks.push(Buffer.from(chunk.subarray(0, remaining)));
        this.stderrBytes += Math.min(remaining, chunk.length);
      }
      if (chunk.length > remaining) this.stderrTruncated = true;
    });
    await new Promise<void>((resolve, reject) => {
      child.once('spawn', resolve);
      child.once('error', (error) => {
        this.onerror?.(error);
        reject(error);
      });
    });
  }
  private force(): void {
    const child = this.child;
    if (!child || child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
    this.forced = true;
    if (process.platform === 'win32')
      spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore',
        timeout: 3000,
      });
    else {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    }
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
  async send(message: JSONRPCMessage): Promise<void> {
    const child = this.child;
    assert(child && !this.closed, 'IDA_TRANSPORT_CLOSED', 'Owned MCP process is closed');
    await new Promise<void>((resolve, reject) => {
      child.stdin.write(serializeMessage(message), 'utf8', (error) => (error ? reject(error) : resolve()));
    });
  }
  async close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closing = (async () => {
      const child = this.child;
      if (!child) {
        this.closed = true;
        return;
      }
      child.stdin.end();
      await this.untilClosed(500);
      if (!this.closed) {
        this.force();
        await this.untilClosed(4000);
      }
      assert(this.closed, 'IDA_CLEANUP_INCOMPLETE', 'Owned MCP process did not close');
      this.buffer.clear();
    })();
    return this.closing;
  }
  private async untilClosed(timeout: number): Promise<void> {
    if (this.closed) return;
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      this.ended,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeout);
      }),
    ]);
    if (timer) clearTimeout(timer);
  }
  stderr() {
    return Buffer.concat(this.stderrChunks).toString('utf8');
  }
  transcript() {
    return {
      bytes: Buffer.concat(this.stdoutChunks),
      received_bytes: this.stdoutBytes,
      truncated: this.stdoutStored < this.stdoutBytes,
      error: this.diagnostic,
    };
  }
}

export interface IdaToolReply {
  value: unknown;
  artifact: import('../types.js').ArtifactRef;
  truncated:boolean;
}
export class IdaSession {
  private client = new Client({ name: 'wirefit-ida', version: '0.1.0' });
  private transport: OwnedTransport;
  private available = new Set<string>();
  private rawBytes = 0;
  private ownedDatabaseCloseAuthorized = false;
  private expectedDatabase: string;
  connected = false;
  constructor(
    private service: WirefitService,
    private result: IdaAnalysisResult,
    configuration: IdaConfiguration,
    input: string,
    database: string,
    cwd: string,
  ) {
    this.expectedDatabase = database;
    this.transport = new OwnedTransport(
      configuration,
      configuration.args.map((arg) => (arg === '{input}' ? input : arg === '{database}' ? database : arg)),
      cwd,
    );
  }
  authorizeOwnedDatabaseClose(identity: Record<string, unknown>): void {
    const actual = typeof identity.idb_path === 'string' ? path.resolve(identity.idb_path) : '';
    const expected = path.resolve(this.expectedDatabase);
    const same =
      process.platform === 'win32' ? actual.toLowerCase() === expected.toLowerCase() : actual === expected;
    this.ownedDatabaseCloseAuthorized =
      identity.owned === true && identity.pid === this.transport.pid && same;
  }
  private async save(value: unknown) {
    const bytes = Buffer.byteLength(JSON.stringify(value), 'utf8');
    this.rawBytes += bytes;
    assert(
      bytes <= MESSAGE_LIMIT && this.rawBytes <= SESSION_LIMIT,
      'IDA_REPLY_BUDGET',
      'IDA raw evidence exceeds its bounded budget',
    );
    const artifact = await this.service.store.putJson(value);
    this.result.artifacts.push(artifact);
    return artifact;
  }
  async connect(signal: AbortSignal, timeout: number): Promise<void> {
    await this.client.connect(this.transport, { signal, timeout });
    this.connected = true;
    this.result.cleanup.pid = this.transport.pid;
    await this.save({
      kind: 'mcp_handshake',
      server: this.client.getServerVersion(),
      capabilities: this.client.getServerCapabilities(),
    });
    let cursor: string | undefined;
    const seen = new Set<string>(),
      tools: unknown[] = [];
    do {
      const page = await this.client.listTools(cursor ? { cursor } : undefined, { signal, timeout });
      await this.save({ kind: 'tool_catalog_page', reply: page });
      tools.push(...page.tools);
      for (const tool of page.tools) this.available.add(tool.name);
      assert(
        tools.length <= 256 && seen.size < 8,
        'IDA_CATALOG_BUDGET',
        'IDA tool catalog exceeded its bounded budget',
      );
      cursor = page.nextCursor;
      if (cursor !== undefined) {
        assert(!seen.has(cursor), 'IDA_CATALOG_CYCLE', 'IDA tool catalog repeated a cursor');
        seen.add(cursor);
      }
    } while (cursor !== undefined);
    this.result.tool_catalog_artifact = await this.save({ kind: 'tool_catalog', tools });
  }
  async call(
    tool: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
    timeout = 60000,
  ): Promise<IdaToolReply> {
    assert(ALLOWED.has(tool), 'IDA_TOOL_FORBIDDEN', 'Tool is outside WireFit read-only allowlist');
    assert(this.available.has(tool), 'IDA_TOOL_UNAVAILABLE', 'IDA did not advertise ' + tool);
    let reply: unknown;
    try {
      reply = await this.client.callTool({ name: tool, arguments: args }, undefined, { signal, timeout });
    } catch (error) {
      await this.save({ kind: 'tool_reply', tool, arguments: args, error: errorRecord(error, 'ida-mcp') });
      throw error;
    }
    const artifact = await this.save({ kind: 'tool_reply', tool, arguments: args, reply });
    assert(
      reply !== null && typeof reply === 'object',
      'IDA_REPLY_INVALID',
      'IDA tool reply must be an object',
    );
    const envelope = reply as Record<string, unknown>;
    if (envelope.isError === true)
      throw new WirefitError('IDA_TOOL_ERROR', tool + ' returned a tool error', { artifact });
    let value = envelope.structuredContent;
    if (value === undefined) {
      const texts = Array.isArray(envelope.content)
        ? envelope.content
            .filter((item: any) => item?.type === 'text' && typeof item.text === 'string')
            .map((item: any) => item.text)
        : [];
      assert(texts.length === 1, 'IDA_REPLY_INVALID', 'IDA reply omitted structured JSON');
      try {
        value = JSON.parse(texts[0]);
      } catch {
        throw new WirefitError('IDA_REPLY_INVALID', 'IDA reply text was not JSON', { artifact });
      }
    }
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Object.keys(value).length === 1 &&
      'result' in value
    )
      value = (value as Record<string, unknown>).result;
    const diagnostic = resultError(value);
    if (diagnostic) throw new WirefitError('IDA_TOOL_ERROR', tool + ': ' + diagnostic, { artifact });
    return { value, artifact, truncated:object(object(envelope._meta).ida_mcp).output_truncated===true };
  }
  async close(): Promise<void> {
    try {
      if (this.connected && this.ownedDatabaseCloseAuthorized) {
        const reply = await this.call('ida_close', {}, undefined, 1500);
        const value = object(reply.value);
        assert(
          value.idb_closed === true && value.owned === true && value.pid === this.transport.pid,
          'IDA_CLOSE_UNVERIFIED',
          'IDA did not confirm closing its owned database',
        );
        this.result.cleanup.idb_closed = true;
      }
    } catch (error) {
      this.result.cleanup.error = errorRecord(error, 'ida-cleanup');
    } finally {
      try {
        await this.client.close();
      } catch (error) {
        this.result.cleanup.error ??= errorRecord(error, 'ida-cleanup');
      }
      try {
        await this.transport.close();
      } catch (error) {
        this.result.cleanup.error ??= errorRecord(error, 'ida-cleanup');
      }
      this.result.cleanup.pid = this.transport.pid;
      this.result.cleanup.process_closed = this.transport.closed;
      this.result.cleanup.forced = this.transport.forced;
      const transcript = this.transport.transcript();
      const wire = await this.service.store.putArtifact(transcript.bytes, 'application/x-ndjson');
      this.result.artifacts.push(wire);
      // Wire bytes are preserved before JSON parsing, including integers beyond JS precision.
      const receipt = await this.service.store.putJson({
        kind: 'stdio_transcript',
        artifact: wire,
        received_bytes: transcript.received_bytes,
        truncated: transcript.truncated,
        error: transcript.error,
      });
      this.result.artifacts.push(receipt);
      const stderr = this.transport.stderr();
      if (stderr || this.transport.stderrTruncated)
        await this.save({ kind: 'stderr', text: stderr, truncated: this.transport.stderrTruncated });
    }
  }
}
export function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
function resultError(value: unknown): string | undefined {
  if (Array.isArray(value)) {
    for (const item of value) {
      const error = resultError(item);
      if (error) return error;
    }
    return;
  }
  const item = object(value);
  if (typeof item.error === 'string' && item.error.length > 0) return item.error.slice(0, 2048);
  if (item.error !== undefined && item.error !== null && item.error !== false && item.error !== '')
    return 'Structured tool error';
}
const ALLOWED = new Set([
  'wirefit_identity',
  'ida_close',
  'server_health',
  'survey_binary',
  'list_funcs',
  'entity_query',
  'type_query',
  'decompile',
  'disasm',
  'basic_blocks',
  'func_profile',
  'xrefs_to',
  'callees',
  'get_bytes',
]);
