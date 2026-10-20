import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import { snapshot, putSnapshot, type BinarySource } from '../binary-files.js';
import { assert, errorRecord, id, WirefitError } from '../shared.js';
import type { WirefitService } from '../service.js';
import type { JobExecutionResult, JobState } from '../jobs.js';
import { loadIdaConfiguration, providerIdentity, validateIdaConfiguration } from './configuration.js';
import { validateIdaAnalysisRequest } from './validation.js';
import { IdaSession, object } from './session.js';
import { validateIdaToolData, normalizeIdaCfg, canonicalIdaAddress } from './normalization.js';
import { resolveIdaSourceScope } from './scope.js';
import { verifyConfiguredIdaProbe } from './probe.js';
import type {
  IdaAnalysisRequest,
  IdaAnalysisResult,
  IdaConfiguration,
  IdaQuery,
  IdaQueryResult,
} from './types.js';

const MAX_INPUT = 128 * 1024 * 1024;
function failed(error: unknown, signal: AbortSignal): WirefitError {
  if (signal.aborted)
    return signal.reason instanceof WirefitError
      ? signal.reason
      : new WirefitError('CANCELLED', 'IDA analysis cancelled; acquired evidence is retained');
  return error instanceof WirefitError
    ? error
    : new WirefitError('IDA_ANALYSIS_FAILED', error instanceof Error ? error.message : String(error));
}
function check(signal: AbortSignal): void {
  if (signal.aborted) throw failed(signal.reason, signal);
}
function samePath(left: unknown, right: string): boolean {
  if (typeof left !== 'string' || !path.isAbsolute(left)) return false;
  return process.platform === 'win32'
    ? path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase()
    : path.resolve(left) === path.resolve(right);
}
async function staging(service: WirefitService, source: BinarySource, resultId: string) {
  const relative = '.ida-work/' + resultId,
    folder = await service.store.resolveRelative(relative, false);
  await mkdir(folder, { recursive: true });
  // A fixed basename keeps source filenames out of IDA's command syntax and preserves the extension for loaders.
  const extension = /^\.[a-z0-9]{1,12}$/i.test(path.extname(source.path))
    ? path.extname(source.path)
    : '.bin';
  const input = await service.store.resolveRelative(relative + '/input' + extension, false),
    database = await service.store.resolveRelative(relative + '/owned.i64', false);
  await writeFile(input, await service.store.readArtifact(source.artifact), { flag: 'wx' });
  const copy = await snapshot(input, MAX_INPUT, true);
  assert(
    copy.sha256 === source.sha256,
    'IDA_STAGE_IDENTITY_MISMATCH',
    'Staged IDA input differs from immutable source',
  );
  return { folder, input, database };
}
function first(value: unknown): Record<string, unknown> {
  return object(Array.isArray(value) ? value[0] : value);
}
function truncated(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(truncated);
  const item = object(value),
    cursor = object(item.cursor);
  return (
    item.truncated === true ||
    item.more === true ||
    typeof item.next_offset === 'number' ||
    typeof cursor.next === 'number' ||
    item.refs_truncated === true
  );
}
async function executeQuery(
  session: IdaSession,
  query: IdaQuery,
  signal: AbortSignal,
  timeout: number,
): Promise<IdaQueryResult> {
  const result: IdaQueryResult = { query, status: 'completed', artifacts: [] };
  const components: Record<string, unknown> = {};
  let successes = 0,
    failures = 0,
    limited = false;
  const call = async (tool: string, args: Record<string, unknown>) => {
    try {
      check(signal);
      const reply = await session.call(tool, args, signal, timeout);
      result.artifacts.push(reply.artifact);
      validateIdaToolData(tool, reply.value, args);
      components[tool] = { status: reply.truncated?'partial':'completed', artifact: reply.artifact, ...(reply.truncated?{truncated:true}:{}) };
      successes++;
      limited ||= reply.truncated||truncated(reply.value);
      return reply.value;
    } catch (error) {
      failures++;
      const detail = errorRecord(failed(error, signal), 'ida-query');
      components[tool] = { status: 'failed', error: detail };
      result.error ??= detail;
      return undefined;
    }
  };
  const paged = query.kind === 'functions' || query.kind === 'strings' || query.kind === 'types';
  if (paged) {
    const options = { filter: query.pattern ?? '', offset: query.offset ?? 0, count: query.limit ?? 100 };
    const tool =
      query.kind === 'functions' ? 'list_funcs' : query.kind === 'strings' ? 'entity_query' : 'type_query';
    const value = await call(tool, {
      queries: query.kind === 'strings' ? { kind: 'strings', ...options } : options,
    });
    if (value !== undefined) {
      const page = first(value);
      assert(Array.isArray(page.data), 'IDA_REPLY_INVALID', 'IDA listing did not contain a data page');
      const items = page.data.map((row) => {
        const item = object(row);
        return typeof item.size === 'number' && !Number.isSafeInteger(item.size)
          ? { ...item, size: null, size_precision: 'unsafe_json_integer' }
          : row;
      });
      result.data = {
        items,
        next_offset: page.next_offset ?? null,
        ...(typeof page.total === 'number' ? { total: page.total } : {}),
      };
    }
  } else if (query.kind === 'overview') {
    const value = await call('server_health', {});
    if (value !== undefined) result.data = { metadata: object(value) };
  } else if (query.kind === 'bytes') {
    const value = await call('get_bytes', { regions: { addr: query.address, size: query.size } });
    if (value !== undefined)
      result.data = { address: query.address, size: query.size, bytes: first(value).data };
  } else if (query.kind === 'xrefs') {
    const value = await call('xrefs_to', { addrs: query.address, limit: 200 });
    if (value !== undefined)
      result.data = {
        address: query.address,
        xrefs: first(value).xrefs ?? [],
        more: first(value).more === true,
      };
  } else if (query.kind === 'function') {
    const data: Record<string, unknown> = { address: query.address };
    const decomp = await call('decompile', {
      addr: query.address,
      include_addresses: true,
      max_lines: 500,
      offset: 0,
    });
    if (decomp !== undefined) {
      const code = object(decomp).code;
      if (typeof code === 'string') data.pseudocode = code;
      else {
        failures++;
        result.error ??= errorRecord(
          new WirefitError('IDA_DECOMPILE_UNAVAILABLE', 'Decompiler returned no pseudocode'),
          'ida-query',
        );
      }
    }
    const disasm = await call('disasm', {
      addr: query.address,
      max_instructions: 500,
      offset: 0,
      include_total: true,
    });
    if (disasm !== undefined) {
      const listing = object(object(disasm).asm);
      if (typeof listing.name === 'string') data.name = listing.name;
      if (Array.isArray(listing.lines))
        data.disassembly = listing.lines.map((row) => ({
          ...object(row),
          addr: canonicalIdaAddress(object(row).addr as string),
        }));
    }
    const blocks = await call('basic_blocks', { addrs: query.address, max_blocks: 200, offset: 0 });
    if (blocks !== undefined) {
      const nodes = first(blocks).blocks;
      if (Array.isArray(nodes)) data.basic_blocks = normalizeIdaCfg(nodes);
    }
    const profile = await call('func_profile', {
      queries: { addr: query.address, count: 1, include_lists: true, max_items: 200 },
    });
    if (profile !== undefined) {
      const item = first(first(profile).data);
      if (typeof item.name === 'string') data.name = item.name;
      if (Array.isArray(item.callers)) data.callers = item.callers;
      if (Array.isArray(item.callees)) data.callees = item.callees;
      limited ||= item.callers_truncated === true || item.callees_truncated === true;
    }
    result.data = data;
  }
  if (failures) result.status = successes ? 'partial' : 'failed';
  if (signal.aborted)
    result.status =
      signal.reason instanceof WirefitError && signal.reason.code === 'TIMEOUT' ? 'failed' : 'cancelled';
  if (limited && result.status === 'completed') result.status = 'partial';
  if (result.data) result.data = { ...result.data, components, ...(limited ? { truncated: true } : {}) };
  if (result.status === 'failed') delete result.data;
  return result;
}
function initial(source: BinarySource, configuration: IdaConfiguration): IdaAnalysisResult {
  return {
    result_id: id('ida_analysis'),
    operation: 'analyze_ida',
    status: 'failed',
    source,
    provider: providerIdentity(configuration),
    database: { input_path: null, path: null, source_sha256: null, identity_verified: false },
    queries: [],
    artifacts: [],
    error: null,
    limitations: [
      'IDA analysis is static evidence from an isolated copy; no native target is executed.',
      'Pseudocode, disassembly and call graphs do not establish runnable output or whole-program equivalence.',
      'Query pages are bounded; truncated results and per-tool failures remain explicit.',
      'Owned worker lifecycle isolation is not an operating-system security sandbox.',
    ],
    validation: { source_unchanged: true, runnable_verified: false, whole_program_equivalence: false },
    cleanup: { owned: true, idb_closed: false, process_closed: true, forced: false, pid: null },
  };
}
async function persist(
  service: WirefitService,
  result: IdaAnalysisResult,
  request: IdaAnalysisRequest,
  signal: AbortSignal,
): Promise<JobExecutionResult> {
  const cancelled = () => {
    result.status = 'cancelled';
    result.error = errorRecord(failed(undefined, signal), 'ida-analysis');
  };
  const publish = () =>
    service.store.putObject('runs', result.result_id, {
      result,
      request,
      model_ids: [],
      candidate_model_id: null,
      dataset_id: null,
      observations_artifact: null,
      comparison_artifact: null,
      test_inputs_artifact: null,
    });
  if (signal.aborted) cancelled();
  await publish();
  if (signal.aborted && result.status !== 'cancelled') {
    result.supersedes_result_id = result.result_id;
    result.result_id = id('ida_cancelled');
    cancelled();
    await publish();
  }
  return {
    result_id: result.result_id,
    status: result.status === 'partial' ? 'completed' : result.status,
    ...(result.status === 'failed' || result.status === 'cancelled'
      ? {
          error:
            result.error ??
            errorRecord(new WirefitError('IDA_ANALYSIS_FAILED', 'IDA analysis failed'), 'ida-analysis'),
        }
      : {}),
  };
}
export async function submitIdaAnalysis(
  service: WirefitService,
  input: IdaAnalysisRequest,
  configuration?: IdaConfiguration,
): Promise<JobState> {
  const request = validateIdaAnalysisRequest(input),
    selected = validateIdaConfiguration(configuration ?? (await loadIdaConfiguration()));
  if (selected.probe_receipt) {
    try {
      await verifyConfiguredIdaProbe(selected);
    } catch (error) {
      throw new WirefitError(
        'IDA_RUNTIME_UNVERIFIED',
        'IDA runtime identity changed or its native probe is not verified: ' +
          (error instanceof Error ? error.message : String(error)),
      );
    }
  } else
    assert(
      configuration !== undefined,
      'IDA_RUNTIME_UNVERIFIED',
      'Default IDA analysis requires a verified native runtime probe',
    );
  const source = await putSnapshot(service, await snapshot(request.file, MAX_INPUT, true)),
    timeout = request.timeout_ms ?? 120000;
  return service.jobs.submit(
    'analyze_ida',
    { ...request, source, provider: providerIdentity(selected) },
    async (externalSignal) => {
      const result = initial(source, selected),
        controller = new AbortController();
      if (!selected.probe_receipt)
        result.limitations.push(
          'This explicitly supplied runtime has no verified native probe. Its provider version and revision are declared configuration identities.',
        );
      const abort = () =>
        controller.abort(
          externalSignal.reason instanceof WirefitError
            ? externalSignal.reason
            : new WirefitError('CANCELLED', 'IDA analysis cancelled'),
        );
      externalSignal.addEventListener('abort', abort, { once: true });
      if (externalSignal.aborted) abort();
      const timer = setTimeout(
        () => controller.abort(new WirefitError('TIMEOUT', 'IDA analysis wall timeout')),
        timeout,
      );
      let session: IdaSession | undefined;
      try {
        check(controller.signal);
        const context = await resolveIdaSourceScope(service, source);
        result.source_scope = context.scope;
        result.artifacts.push(...context.artifacts);
        result.limitations.push(context.scope.description);
        const work = await staging(service, source, result.result_id);
        check(controller.signal);
        session = new IdaSession(service, result, selected, work.input, work.database, work.folder);
        result.cleanup.process_closed = false;
        await session.connect(controller.signal, timeout);
        const identity = object(
          (await session.call('wirefit_identity', {}, controller.signal, timeout)).value,
        );
        session.authorizeOwnedDatabaseClose(identity);
        result.database = {
          input_path: typeof identity.input_path === 'string' ? identity.input_path : null,
          path: typeof identity.idb_path === 'string' ? identity.idb_path : null,
          source_sha256: typeof identity.sha256 === 'string' ? identity.sha256 : null,
          identity_verified: false,
          ...(typeof identity.imagebase === 'string' ? { imagebase: identity.imagebase } : {}),
          ...(typeof identity.version === 'string' ? { version: identity.version } : {}),
        };
        assert(
          samePath(identity.input_path, work.input) &&
            samePath(identity.idb_path, work.database) &&
            identity.sha256 === source.sha256,
          'IDA_SOURCE_IDENTITY_MISMATCH',
          'Connected IDA database does not match this job staged input/hash/database',
        );
        assert(
          identity.owned === true &&
            identity.pid === result.cleanup.pid &&
            identity.revision === selected.provider.revision,
          'IDA_PROVIDER_IDENTITY_MISMATCH',
          'IDA process ownership or source revision differs from administrator configuration',
        );
        result.database.identity_verified = true;
        if (typeof identity.analysis_completed === 'boolean')
          result.database.analysis_completed = identity.analysis_completed;
        if (identity.analysis_completed === false)
          result.limitations.push(
            'IDA native auto-analysis reached its time budget; the database and subsequent evidence may be incomplete.',
          );
        for (const query of request.queries) {
          check(controller.signal);
          const item = await executeQuery(session, query, controller.signal, timeout);
          result.queries.push(item);
          check(controller.signal);
        }
        const completed = result.queries.filter((item) => item.status === 'completed').length;
        result.status =
          completed === result.queries.length
            ? 'completed'
            : result.queries.some((item) => item.status === 'completed' || item.status === 'partial')
              ? 'partial'
              : 'failed';
        if (result.status === 'failed')
          result.error =
            result.queries.find((item) => item.error)?.error ??
            errorRecord(new WirefitError('IDA_ANALYSIS_FAILED', 'No IDA query completed'), 'ida-analysis');
        if (result.status === 'completed' && identity.analysis_completed === false) result.status = 'partial';
      } catch (error) {
        const detail = failed(error, controller.signal);
        result.status = detail.code === 'CANCELLED' ? 'cancelled' : 'failed';
        result.error = errorRecord(detail, 'ida-analysis');
        for (const query of request.queries.slice(result.queries.length))
          result.queries.push({ query, status: result.status, error: result.error, artifacts: [] });
      } finally {
        clearTimeout(timer);
        externalSignal.removeEventListener('abort', abort);
        if (session) {
          try {
            await session.close();
          } catch (error) {
            result.cleanup.error = errorRecord(error, 'ida-cleanup');
          }
        }
        if (!result.cleanup.process_closed || result.cleanup.error) {
          if (result.status === 'completed') result.status = 'partial';
          result.error ??=
            result.cleanup.error ??
            errorRecord(
              new WirefitError('IDA_CLEANUP_INCOMPLETE', 'Owned worker cleanup is incomplete'),
              'ida-cleanup',
            );
        }
        try {
          result.validation.source_unchanged =
            (await snapshot(source.path, MAX_INPUT, true)).sha256 === source.sha256;
        } catch {
          result.validation.source_unchanged = false;
        }
        if (!result.validation.source_unchanged) {
          result.status = 'failed';
          result.error = errorRecord(
            new WirefitError('SOURCE_CHANGED', 'Original input changed after its immutable snapshot'),
            'ida-analysis',
          );
        }
      }
      return persist(service, result, request, externalSignal);
    },
    Math.min(86400000, timeout + 10000),
  );
}
