import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { parseImmutableEvidenceBundle, type EvidenceBundle } from '../vendor/rea/src/domain/evidenceBundle.js';
import { jsonValueValidationIssue } from '../vendor/rea/src/domain/jsonValue.js';
import type { Evidence } from '../vendor/rea/src/domain/evidence.js';
import { WirefitError, assert } from './shared.js';

/** This is the release commit from npm's published SLSA provenance, not same-version main. */
export const REA_ADAPTER_IDENTITY = Object.freeze({
  parser: 'wirefit.rea-portable.v1', parser_commit: '27dc42d10249f0410904a75c0997842eb03b931c',
  package: 'rea-agents', package_version: '6.7.0',
  catalog_digest: '96d8f6e6ea1b1ba13557216624a3461c738729d53c79b4b0100d1f3a3a32441c',
});
const sourceBundles = new WeakMap<object, string>();
export function reaRecordBundleHash(record: object): string | undefined { return sourceBundles.get(record); }
export interface ImportedEvidence {
  status: 'supported' | 'attachment_only'; records: readonly Evidence[];
  identity: typeof REA_ADAPTER_IDENTITY; bundle?: EvidenceBundle;
  raw: unknown; diagnostics: {code: string; message: string}[];
}

/** Authenticate with the unchanged upstream envelope, profile, graph and identity validator. */
export function importPortableEvidence(input: unknown, bundleSha256?: string): ImportedEvidence {
  try {
    const issue = jsonValueValidationIssue(input);
    assert(issue === undefined, 'INVALID_REA_JSON', issue ?? 'Invalid JSON');
    if (bundleSha256 !== undefined) assert(/^[0-9a-f]{64}$/.test(bundleSha256), 'INVALID_REA_HASH', 'Invalid bundle SHA-256');
    const bundle = parseImmutableEvidenceBundle(input);
    if (bundleSha256 !== undefined) for (const record of bundle.records) sourceBundles.set(record, bundleSha256);
    return { status: 'supported', records: bundle.records, identity: REA_ADAPTER_IDENTITY, bundle, raw: input, diagnostics: [] };
  } catch (error) {
    return { status: 'attachment_only', records: [], identity: REA_ADAPTER_IDENTITY, raw: input,
      diagnostics: [{ code: 'UNSUPPORTED_OR_INVALID_REA_BUNDLE', message: error instanceof Error ? error.message : String(error) }] };
  }
}

export interface ReaReply {
  ok: boolean; value?: unknown; diagnostic?: unknown; metadata: unknown; raw: unknown;
}
/** Metadata stays separate from canonical Evidence. Error text is diagnostic data. */
export function interpretReaReply(reply: unknown): ReaReply {
  assert(reply !== null && typeof reply === 'object', 'INVALID_REA_REPLY', 'REA reply must be an object');
  const object = reply as Record<string, unknown>;
  const metadata = object._meta ?? null;
  if (object.isError === true) {
    const texts = Array.isArray(object.content) ? object.content.filter((item): item is {type:'text';text:string} =>
      item !== null && typeof item === 'object' && item.type === 'text' && typeof item.text === 'string').map(item => item.text) : [];
    const text = texts.join('\n');
    let diagnostic: unknown = text;
    try { diagnostic = JSON.parse(text); } catch { /* Preserve non-JSON errors verbatim. */ }
    return { ok: false, diagnostic, metadata, raw: reply };
  }
  assert(Object.hasOwn(object, 'structuredContent'), 'INVALID_REA_REPLY', 'Successful REA reply omitted structuredContent');
  return { ok: true, value: object.structuredContent, metadata, raw: reply };
}

export interface ReaAcquireOptions {
  command: string; args?: string[]; cwd?: string; env?: Record<string,string>;
  target?: string; provider?: string; functionAddress?: string;
  /** Absolute destination. REA atomically publishes only a complete canonical bundle. */
  destination: string; timeoutMs?: number; recoveryTimeoutMs?: number;
  /** Called after export and authentication, before close_binary clears retained records. */
  persist?: (evidence: ImportedEvidence, bytes: Uint8Array) => Promise<void>;
}
export interface ReaAcquisition {
  status: 'completed'|'failed'|'cancelled'; capabilities: {before: unknown; after: unknown};
  server: unknown; tools: unknown[]; replies: {name:string;reply:ReaReply}[];
  imported?: ImportedEvidence; bundleSha256?: string; persisted: boolean;
  cleanup: {closed: boolean; diagnostic?: unknown}; diagnostics: {code:string;message:string}[];
}

function checkSessionIdentity(value: unknown): void {
  const object = (item: unknown): Record<string,unknown> => item !== null && typeof item === 'object' && !Array.isArray(item) ? item as Record<string,unknown> : {};
  const identity = object(object(object(value).result).server_identity);
  const providerPackage = object(identity.package);
  const digest = object(object(identity.catalog).digests).combined_sha256;
  assert(providerPackage.name === REA_ADAPTER_IDENTITY.package && providerPackage.version === REA_ADAPTER_IDENTITY.package_version && digest === REA_ADAPTER_IDENTITY.catalog_digest,
    'UNSUPPORTED_REA_SERVER_IDENTITY','Live REA package/catalog does not match the pinned adapter; raw export recovery remains available');
}

/** Uses one owned public MCP session, retaining export recovery even after caller cancellation. */
export async function acquireEvidence(options: ReaAcquireOptions, signal?: AbortSignal): Promise<ReaAcquisition> {
  assert(typeof options.command === 'string' && options.command.length > 0 && !options.command.includes('\0'), 'INVALID_REA_COMMAND', 'REA command must be nonempty');
  assert(path.isAbsolute(options.destination) && !options.destination.includes('\0'), 'INVALID_REA_DESTINATION', 'REA export destination must be absolute');
  const timeout = options.timeoutMs ?? 60_000;
  const recoveryTimeout = options.recoveryTimeoutMs ?? 10_000;
  for (const value of [timeout, recoveryTimeout]) assert(Number.isSafeInteger(value) && value > 0 && value <= 600_000, 'INVALID_REA_TIMEOUT', 'REA timeout must be 1..600000 ms');
  if (options.target !== undefined) assert(path.isAbsolute(options.target), 'INVALID_REA_TARGET', 'REA target path must be absolute');
  const result: ReaAcquisition = { status: 'failed', capabilities: {before:null,after:null}, server:null, tools:[], replies:[], persisted:false, cleanup:{closed:false}, diagnostics:[] };
  const client = new Client({name:'wirefit',version:'0.1.0'});
  const transport = new StdioClientTransport({command:options.command,args:options.args,cwd:options.cwd,env:options.env,stderr:'pipe'});
  let connected = false;
  const available = new Set<string>();
  const expectations = {expected_package_version:REA_ADAPTER_IDENTITY.package_version,expected_catalog_digest:REA_ADAPTER_IDENTITY.catalog_digest};
  const call = async (name: string, args: Record<string,unknown>, recovery = false): Promise<ReaReply> => {
    assert(available.has(name), 'REA_TOOL_UNAVAILABLE', `REA did not advertise ${name}`);
    const reply = interpretReaReply(await client.callTool({name,arguments:args}, undefined,
      {timeout:recovery ? recoveryTimeout : timeout, ...(recovery ? {} : {signal})}));
    result.replies.push({name,reply});
    if (!reply.ok) throw new WirefitError('REA_TOOL_ERROR', `${name} returned an error`, reply.diagnostic);
    return reply;
  };
  // stderr must be drained even when the caller does not request a log.
  let stderr = '';
  transport.stderr?.on('data', (chunk: Buffer) => { if (stderr.length < 65_536) stderr += chunk.toString('utf8').slice(0,65_536-stderr.length); });
  try {
    await client.connect(transport, {timeout,signal}); connected = true;
    result.server = {version:client.getServerVersion(),capabilities:client.getServerCapabilities()};
    let cursor: string | undefined;
    const seen = new Set<string>();
    do {
      const page = await client.listTools(cursor ? {cursor} : undefined, {timeout,signal});
      result.tools.push(...page.tools);
      for (const tool of page.tools) available.add(tool.name);
      cursor = page.nextCursor;
      if (cursor !== undefined) { assert(!seen.has(cursor), 'REA_CURSOR_CYCLE', 'REA tools pagination repeated a cursor'); seen.add(cursor); }
      assert(result.tools.length <= 4096, 'REA_TOOL_BUDGET', 'REA advertised too many tools');
    } while (cursor !== undefined);
    result.capabilities.before = (await call('binary_session',expectations)).value;
    checkSessionIdentity(result.capabilities.before);
    if (options.target !== undefined) await call('open_binary',{path:options.target,...(options.provider ? {provider_id:options.provider} : {})});
    // Availability is target dependent. Always refresh after the attempted binding.
    result.capabilities.after = (await call('binary_session',expectations)).value;
    checkSessionIdentity(result.capabilities.after);
    if (options.functionAddress !== undefined) {
      assert(options.target !== undefined,'REA_TARGET_REQUIRED','Function analysis requires a target');
      await call('analyze_function',{procedure:options.functionAddress});
    }
    result.status = 'completed';
  } catch (error) {
    result.status = signal?.aborted ? 'cancelled' : 'failed';
    result.diagnostics.push({code:error instanceof WirefitError ? error.code : (signal?.aborted ? 'CANCELLED':'REA_ACQUIRE_FAILED'),message:error instanceof Error ? error.message:String(error)});
  } finally {
    if (connected) {
      if (result.capabilities.after === null && available.has('binary_session')) {
        try { result.capabilities.after = (await call('binary_session',expectations,true)).value; }
        catch (error) { result.diagnostics.push({code:'REA_CAPABILITIES_UNAVAILABLE',message:error instanceof Error ? error.message:String(error)}); }
      }
      // A fresh bounded request deliberately does not inherit the aborted signal.
      try {
        await call('export_evidence_bundle',{path:options.destination,overwrite:false},true);
        const info = await stat(options.destination);
        assert(info.size <= 64*1024*1024,'REA_BUNDLE_BUDGET','REA bundle exceeds the 64 MiB import budget');
        const bytes = await readFile(options.destination);
        result.bundleSha256 = createHash('sha256').update(bytes).digest('hex');
        result.imported = importPortableEvidence(JSON.parse(bytes.toString('utf8')),result.bundleSha256);
        assert(result.imported.status === 'supported','REA_EXPORTED_BUNDLE_INVALID','Exported REA bundle failed canonical authentication');
        if (options.persist !== undefined) await options.persist(result.imported,bytes);
        result.persisted = true;
      } catch (error) {
        result.status = signal?.aborted ? 'cancelled' : 'failed';
        result.diagnostics.push({code:'REA_EVIDENCE_NOT_PERSISTED',message:error instanceof Error ? error.message:String(error)});
      }
      try { await call('close_binary',{},true); result.cleanup.closed = true; }
      catch (error) {
        result.cleanup.diagnostic = error instanceof WirefitError ? error.details : String(error);
        if (result.status === 'completed') result.status = 'failed';
        result.diagnostics.push({code:'REA_CLEANUP_INCOMPLETE',message:error instanceof Error ? error.message:String(error)});
      }
    }
    try { await client.close(); } catch (error) { result.cleanup.diagnostic ??= String(error); }
    if (stderr) result.diagnostics.push({code:'REA_STDERR',message:stderr});
  }
  return result;
}
