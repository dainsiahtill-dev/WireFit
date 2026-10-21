import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { WirefitService } from './service.js';
import {
  submitBinaryInspection,
  submitBinaryUnpack,
  validateBinaryToolchain,
  type BinaryToolchain,
} from './binary-service.js';
import { submitBinaryTrace, validateNativeTraceRequest } from './native-trace.js';
import {submitIdaAnalysis,idaCapabilities,validateIdaAnalysisRequest,type IdaQuery} from './ida/index.js';
import { CaseStore } from './store.js';
import { loadModel } from './repository.js';
import { evaluateModel } from './verification.js';
import { defaultMapping } from './model.js';
import {
  assert,
  WirefitError,
  errorRecord,
  id,
  readJson,
  readJsonl,
  resolveBudget,
  rootDir,
  hashObject,
  validateSchema,
} from './shared.js';
import { bv, bool } from './values.js';
import type { JobState } from './jobs.js';
import type { OracleBinding, InputSample } from './oracle.js';
import type {
  Budget,
  ComparisonPolicy,
  CoreValue,
  Domain,
  Mapping,
  ValueMap,
  Signature,
} from './types.js';
const commands: Record<string, string[]> = {
  doctor: [],
  'ida status': [],
  'ida analyze': ['case','file','query','timeout'],
  'case create': ['dir'],
  'model import': ['case', 'file'],
  'model evaluate': ['case', 'model', 'inputs'],
  'model simplify': ['case', 'model', 'budget', 'domain', 'search'],
  'model fit': ['case', 'dataset', 'template-model', 'backend', 'budget', 'training'],
  'model lift': ['case', 'evidence', 'output', 'cutpoints'],
  'oracle register': ['case', 'manifest'],
  'dataset import': ['case', 'manifest', 'artifact-root'],
  'dataset collect': ['case', 'oracle', 'inputs', 'policy', 'max-calls'],
  'evidence import': ['case', 'bundle'],
  'binary inspect': ['case', 'file', 'config', 'timeout'],
  'binary trace': ['case', 'file', 'config', 'plan'],
  'binary unpack': ['case', 'file', 'backend', 'config', 'timeout', 'target-timeout'],
  'evidence acquire': [
    'case',
    'config',
    'target',
    'provider',
    'procedure',
    'command',
    'args',
    'cwd',
    'timeout',
  ],
  compare: [
    'case',
    'left',
    'right',
    'left-oracle',
    'right-oracle',
    'domain',
    'mapping',
    'mode',
    'inputs',
    'dataset',
    'policy',
    'budget',
  ],
  'experiment run': ['case', 'request'],
  'research list': [],
  'research spec': ['direction'],
  'research run': ['case', 'direction', 'budget'],
  'research recheck': ['case', 'run'],
  jobs: ['case'],
  'job show': ['case', 'job'],
  show: ['case', 'kind', 'id'],
  'report show': ['case', 'run', 'section', 'offset', 'limit'],
  'report export': ['case', 'run', 'out'],
  mcp: ['case'],
};
interface Parsed {
  command: string;
  options: Record<string, string | boolean>;
}
function parse(argv: string[]): Parsed {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === 'help')
    return { command: 'help', options: {} };
  let command = argv[0]!,
    offset = 1;
  if (argv[1] && !argv[1].startsWith('--')) {
    command += ' ' + argv[1];
    offset++;
  }
  assert(Object.hasOwn(commands, command), 'CLI_USAGE', 'Unknown command: ' + command);
  const options: Record<string, string | boolean> = {};
  const flags = new Set([
    'json',
    'help',
    ...(command === 'mcp' ? ['create'] : []),
    ...(command === 'binary unpack' ? ['no-copy-dependencies'] : []),
  ]);
  for (let i = offset; i < argv.length; i++) {
    const token = argv[i]!;
    assert(/^--[a-z][a-z-]*(?:=.*)?$/.test(token), 'CLI_USAGE', 'Unexpected argument: ' + token);
    const equals = token.indexOf('='),
      key = token.slice(2, equals < 0 ? undefined : equals);
    assert(!Object.hasOwn(options, key), 'CLI_USAGE', 'Duplicate option --' + key);
    assert(
      flags.has(key) || commands[command]!.includes(key),
      'CLI_USAGE',
      'Unknown option --' + key,
    );
    if (flags.has(key)) {
      assert(equals < 0, 'CLI_USAGE', 'Flag --' + key + ' takes no value');
      options[key] = true;
    } else {
      const value = equals < 0 ? argv[++i] : token.slice(equals + 1);
      assert(
        typeof value === 'string' && value.length > 0 && !value.startsWith('--'),
        'CLI_USAGE',
        'Missing value for --' + key,
      );
      options[key] = value;
    }
  }
  if (options.help) return { command: 'help', options: {} };
  if (command === 'compare') {
    const model = options.left !== undefined || options.right !== undefined,
      oracle = options['left-oracle'] !== undefined || options['right-oracle'] !== undefined;
    assert(model !== oracle, 'CLI_USAGE', 'Choose --left/--right or --left-oracle/--right-oracle');
    assert(
      model
        ? typeof options.left === 'string' && typeof options.right === 'string'
        : typeof options['left-oracle'] === 'string' && typeof options['right-oracle'] === 'string',
      'CLI_USAGE',
      'Both sides of the selected comparison are required',
    );
    assert(
      !oracle || (options.mode === undefined && options.dataset === undefined),
      'CLI_USAGE',
      'Oracle comparison cannot use model mode or dataset flags',
    );
    assert(!(options.inputs && options.dataset), 'CLI_USAGE', 'Choose --inputs or --dataset');
  }
  return { command, options };
}
const json = (value: unknown) => process.stdout.write(JSON.stringify(value) + '\n');
const progress = (value: unknown) => process.stderr.write(JSON.stringify(value) + '\n');
function required(options: Parsed['options'], key: string): string {
  const value = options[key];
  assert(typeof value === 'string', 'CLI_USAGE', 'Required option --' + key);
  return value;
}
function integer(options: Parsed['options'], key: string, fallback: number): number {
  const value = options[key];
  if (value === undefined) return fallback;
  assert(
    typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value),
    'CLI_USAGE',
    '--' + key + ' must be an integer',
  );
  const result = Number(value);
  assert(Number.isSafeInteger(result), 'CLI_USAGE', '--' + key + ' exceeds safe integer range');
  return result;
}
async function optionalJson<T>(options: Parsed['options'], key: string, fallback: T): Promise<T> {
  return typeof options[key] === 'string' ? readJson<T>(options[key] as string) : fallback;
}
function binaryText(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 4096 &&
    !value.includes('\0')
  );
}
function binaryToolchain(value: unknown): BinaryToolchain {
  try {
    validateBinaryToolchain(value);
    return value;
  } catch (error) {
    if (error instanceof WirefitError && error.code === 'BINARY_REQUEST_INVALID')
      throw new WirefitError('CLI_USAGE', error.message);
    throw error;
  }
}
function binaryInteger(options: Parsed['options'], key: string, maximum: number): number {
  const value = integer(options, key, 0);
  assert(value >= 1 && value <= maximum, 'CLI_USAGE', '--' + key + ' must be 1..' + maximum);
  return value;
}
async function inputArtifact(service: WirefitService, file: string) {
  const rows = await readJsonl<InputSample>(file);
  assert(rows.length > 0, 'EMPTY_SAMPLES', 'Input plan must be nonempty');
  for (const row of rows) validateSchema('input-sample', row);
  return service.store.putArtifact(
    Buffer.from(await readFile(file, 'utf8'), 'utf8'),
    'application/x-ndjson',
  );
}
function foregroundResult(value: unknown): unknown {
  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (value as Record<string, unknown>).operation === 'acquire_evidence'
  ) {
    const source = value as Record<string, unknown>;
    const summary = Object.fromEntries(
      [
        'result_id',
        'operation',
        'status',
        'persisted',
        'cleanup',
        'diagnostics',
        'saved',
        'bundleSha256',
        'server',
        'raw_artifact',
      ]
        .filter((key) => Object.hasOwn(source, key))
        .map((key) => [key, source[key]]),
    );
    return {
      ...summary,
      tool_count:
        typeof source.tool_count === 'number'
          ? source.tool_count
          : Array.isArray(source.tools)
            ? source.tools.length
            : 0,
      raw_result: { kind: 'runs', id: source.result_id },
    };
  }
  return value;
}
async function foreground(
  service: WirefitService,
  submit: () => Promise<JobState>,
): Promise<{ value: unknown; code: number }> {
  let interrupted = false,
    owned: string | undefined;
  let cancelling: Promise<unknown> | undefined;
  const cancel = () => {
    interrupted = true;
    if (owned && !cancelling)
      cancelling = service.jobs
        .cancel(owned)
        .catch((error) => progress({ event: 'cancel_error', error: errorRecord(error, 'cli') }));
  };
  process.on('SIGINT', cancel);
  process.on('SIGTERM', cancel);
  let timer: ReturnType<typeof setInterval> | undefined;
  try {
    const job = await submit();
    owned = job.job_id;
    progress({ event: 'job_submitted', job_id: owned, status: job.status });
    if (interrupted) cancel();
    timer = setInterval(() => progress({ event: 'job_waiting', job_id: owned }), 5000);
    timer.unref();
    const final = await service.jobs.wait(owned);
    await cancelling;
    progress({ event: 'job_finished', job_id: owned, status: final.status });
    const result = final.result_id
      ? foregroundResult(await service.getResult(final.result_id))
      : null;
    const record = final.result_id
      ? await service.store.getObject<{
          candidate_model_id?: string | null;
          dataset_id?: string | null;
        }>('runs', final.result_id)
      : null;
    return {
      value: {
        job: final,
        result,
        candidate_model_id: record?.candidate_model_id ?? null,
        dataset_id:
          record?.dataset_id ??
          (result && typeof result === 'object'
            ? ((result as Record<string, unknown>).dataset_id ?? null)
            : null),
      },
      code:
        interrupted || final.status === 'cancelled' ? 130 : final.status === 'completed' ? 0 : 1,
    };
  } finally {
    if (timer) clearInterval(timer);
    process.removeListener('SIGINT', cancel);
    process.removeListener('SIGTERM', cancel);
  }
}
async function readOnly(command: string, options: Parsed['options']): Promise<unknown> {
  const store = await CaseStore.open(required(options, 'case'), false);
  try {
    if (command === 'jobs')
      return { jobs: (await store.listObjects<JobState>('jobs')).map((x) => x.value) };
    if (command === 'job show') return store.getObject<JobState>('jobs', required(options, 'job'));
    if (command === 'show')
      return store.getObject(required(options, 'kind'), required(options, 'id'));
    if (command === 'model evaluate') {
      const model = await loadModel(store, required(options, 'model')),
        file = required(options, 'inputs');
      if (/\.(jsonl|ndjson)$/i.test(file)) {
        const rows = await readJsonl<InputSample>(file);
        return {
          model_id: model.model_id,
          observations: rows.map((row) => {
            validateSchema('input-sample', row);
            return {
              sample_id: row.sample_id,
              inputs: row.inputs,
              outputs: evaluateModel(model, row.inputs),
            };
          }),
        };
      }
      const inputs = await readJson<ValueMap>(file);
      return { model_id: model.model_id, inputs, outputs: evaluateModel(model, inputs) };
    }
    if (command === 'research recheck') {
      const { recheckResearchRunFromStore } = await import('./research/recheck.js');
      const outcome = await recheckResearchRunFromStore(store, required(options, 'run'));
      return {
        run: required(options, 'run'),
        status: outcome.mismatches.length === 0 ? 'agreed' : 'mismatch',
        checked_count: outcome.checked_count,
        agreed_count: outcome.agreed_count,
        mismatches: outcome.mismatches,
      };
    }
    const section = typeof options.section === 'string' ? options.section : 'result',
      record = await store.getObject<any>('runs', required(options, 'run'));
    const value =
      section === 'result'
        ? record.result
        : section === 'request'
          ? record.request
          : section === 'audit'
            ? record.result?.audit ?? null
            : section === 'counterexamples' && record.comparison_artifact
              ? JSON.parse((await store.readArtifact(record.comparison_artifact)).toString('utf8'))
              : null;
    assert(value !== null, 'REPORT_SECTION_UNAVAILABLE', 'Requested report section is unavailable');
    const offset = integer(options, 'offset', 0),
      limit = integer(options, 'limit', 100);
    assert(limit > 0 && limit <= 1000, 'PAGINATION_INVALID', 'Limit must be 1..1000');
    return Array.isArray(value)
      ? { section, offset, limit, total: value.length, data: value.slice(offset, offset + limit) }
      : { section, data: value };
  } finally {
    await store.close();
  }
}
function validateReaOptions(value: Record<string, unknown>): void {
  for (const key of ['command', 'cwd', 'target', 'provider', 'functionAddress'])
    if (value[key] !== undefined)
      assert(
        typeof value[key] === 'string' &&
          (value[key] as string).length > 0 &&
          !(value[key] as string).includes('\0'),
        'CLI_USAGE',
        'REA ' + key + ' must be a nonempty string',
      );
  if (value.args !== undefined)
    assert(
      Array.isArray(value.args) &&
        value.args.length <= 128 &&
        value.args.every((arg) => typeof arg === 'string' && !arg.includes('\0')),
      'CLI_USAGE',
      'REA args must be a JSON string array',
    );
  for (const key of ['timeoutMs', 'recoveryTimeoutMs'])
    if (value[key] !== undefined)
      assert(
        Number.isSafeInteger(value[key]) &&
          (value[key] as number) >= 1 &&
          (value[key] as number) <= 600000,
        'CLI_USAGE',
        'REA ' + key + ' must be 1..600000 ms',
      );
  if (value.env !== undefined) {
    assert(
      value.env !== null &&
        typeof value.env === 'object' &&
        !Array.isArray(value.env) &&
        Object.keys(value.env).length <= 64,
      'CLI_USAGE',
      'REA env must be an environment map',
    );
    assert(
      Object.entries(value.env).every(
        ([key, val]) =>
          /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) &&
          typeof val === 'string' &&
          val.length <= 32768 &&
          !val.includes('\0'),
      ),
      'CLI_USAGE',
      'REA environment entries must be strings without NUL',
    );
  }
}
function automaticMapping(left: Signature, right: Signature): Mapping {
  assert(
    left.outputs.length === right.outputs.length,
    'INVALID_MAPPING',
    'Different output sets require an explicit --mapping selection',
  );
  return defaultMapping(left, right);
}
async function experiment(
  service: WirefitService,
  command: string,
  options: Parsed['options'],
): Promise<unknown> {
  if (command === 'experiment run') return readJson(required(options, 'request'));
  const budget = resolveBudget(await optionalJson<Partial<Budget>>(options, 'budget', {}));
  const base = { schema_version: 1, experiment_id: id('experiment'), budget };
  if (command === 'model fit')
    return {
      ...base,
      operation: 'fit_numeric',
      dataset_id: required(options, 'dataset'),
      template_model_id: required(options, 'template-model'),
      backend: options.backend ?? 'handwired',
      training: await optionalJson(options, 'training', {
        optimizer: options.backend === 'analytic_baseline' ? 'closed_form' : 'adam',
        learning_rate: '0.001',
        loss: 'mse',
        batch_size: 256,
        restarts: 1,
        validation_interval: 10,
      }),
    };
  if (command === 'model simplify') {
    const model = await loadModel(service.store, required(options, 'model'));
    assert(model.kind === 'bv_dag', 'PROFILE_MISMATCH', 'Simplification requires a BV model');
    const constants: CoreValue[] = model.inputs.flatMap<CoreValue>((p) =>
      p.type.kind === 'bv'
        ? [bv(0n, p.type.width), bv(1n, p.type.width), bv(-1n, p.type.width)]
        : [bool(false), bool(true)],
    );
    constants.push(...model.nodes.filter((n) => n.op === 'const').map((n) => n.attrs.value!));
    const seen = new Set<string>();
    return {
      ...base,
      operation: 'simplify',
      reference_model_id: model.model_id,
      domain: await optionalJson(options, 'domain', model.domain),
      search: await optionalJson(options, 'search', {
        grammar: [
          'bv_add',
          'bv_sub',
          'bv_mul',
          'bv_and',
          'bv_or',
          'bv_xor',
          'bv_not',
          'bv_neg',
          'bv_shl',
          'bv_lshr',
          'bv_ashr',
          'bv_ult',
          'bv_slt',
          'select',
        ],
        constants: constants
          .filter((v) => {
            const hash = hashObject(v);
            if (seen.has(hash)) return false;
            seen.add(hash);
            return true;
          })
          .slice(0, 64),
        objective: 'node_count',
      }),
    };
  }
  if (options['left-oracle']) {
    const left = await service.store.getObject<OracleBinding>(
        'oracles',
        required(options, 'left-oracle'),
      ),
      right = await service.store.getObject<OracleBinding>(
        'oracles',
        required(options, 'right-oracle'),
      );
    const mapping = options.mapping
      ? await readJson<Mapping>(required(options, 'mapping'))
      : automaticMapping(left.manifest.signature, right.manifest.signature);
    progress({ event: 'input_output_mapping', mapping });
    return {
      ...base,
      operation: 'compare_oracles',
      left_oracle_id: left.oracle_id,
      right_oracle_id: right.oracle_id,
      signature: left.manifest.signature,
      domain: await optionalJson(options, 'domain', left.manifest.domain),
      mapping,
      inputs_artifact: await inputArtifact(service, required(options, 'inputs')),
      comparison_policy: await readJson<ComparisonPolicy>(required(options, 'policy')),
    };
  }
  const left = await loadModel(service.store, required(options, 'left')),
    right = await loadModel(service.store, required(options, 'right'));
  const mapping = options.mapping
    ? await readJson<Mapping>(required(options, 'mapping'))
    : automaticMapping(left, right);
  progress({ event: 'input_output_mapping', mapping });
  const domain = await optionalJson<Domain>(options, 'domain', left.domain),
    mode = options.mode ?? (left.kind === 'bv_dag' ? 'exact_bv' : 'sampled_fp32');
  if (mode === 'exact_bv') {
    assert(
      !options.inputs && !options.dataset && !options.policy,
      'CLI_USAGE',
      'Exact BV comparison does not use sample or policy flags',
    );
    return {
      ...base,
      operation: 'compare_models',
      mode,
      left_model_id: left.model_id,
      right_model_id: right.model_id,
      domain,
      mapping,
    };
  }
  assert(mode === 'sampled_fp32', 'CLI_USAGE', 'Mode must be exact_bv or sampled_fp32');
  assert(
    !!options.inputs !== !!options.dataset,
    'CLI_USAGE',
    'Sampled FP32 comparison requires --inputs or --dataset',
  );
  return {
    ...base,
    operation: 'compare_models',
    mode,
    left_model_id: left.model_id,
    right_model_id: right.model_id,
    domain,
    mapping,
    comparison_policy: await readJson<ComparisonPolicy>(required(options, 'policy')),
    sample_source: options.dataset
      ? { kind: 'dataset', dataset_id: required(options, 'dataset') }
      : {
          kind: 'inputs_artifact',
          artifact: await inputArtifact(service, required(options, 'inputs')),
        },
  };
}
export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  if(argv[0]==='web')return (await import('./web/main.js')).runWeb(argv.slice(1));
  const { command, options } = parse(argv);
  if (command === 'help') {
    json({
      product: 'wirefit',
      usage: 'wirefit <command> [options]',
      commands: [...Object.keys(commands), 'web'],
      help: 'See docs/cli.md. Commands write one JSON result to stdout; foreground progress goes to stderr.',
    });
    return 0;
  }
  if (command === 'doctor') {
    json(await WirefitService.capabilities());
    return 0;
  }
  if(command==='ida status'){json(await idaCapabilities(rootDir));return 0;}
  if (command === 'research list' || command === 'research spec') {
    const { researchCatalog, researchDirection } = await import('./research/index.js');
    if (command === 'research list') {
      json({
        directions: researchCatalog().map((direction) => ({
          direction_id: direction.direction_id,
          title: direction.title,
          corpus_role: direction.corpus_role,
          claim_count: direction.claims.length,
          primary_claim_id: direction.primary_claim_id,
        })),
      });
      return 0;
    }
    const directionId = required(options, 'direction');
    const spec = researchDirection(directionId);
    assert(spec !== null, 'CLI_USAGE', 'Unknown research direction: ' + directionId);
    json(spec);
    return 0;
  }
  if (command === 'mcp') {
    const { startMcp } = await import('./mcp.js');
    await startMcp({ caseDir: required(options, 'case'), create: options.create === true });
    return 0;
  }
  if (command === 'case create') {
    const service = await WirefitService.create(required(options, 'dir'));
    try {
      json({ case_dir: service.store.root, product: 'Wirefit' });
    } finally {
      await service.close();
    }
    return 0;
  }
  if (['jobs', 'job show', 'show', 'model evaluate', 'report show', 'research recheck'].includes(command)) {
    json(await readOnly(command, options));
    return 0;
  }
  const service = await WirefitService.open(required(options, 'case'));
  let result: unknown,
    code = 0;
  try {
    if (command === 'model import') result = await service.importModel(required(options, 'file'));
    else if (command === 'oracle register')
      result = await service.registerOracle(required(options, 'manifest'));
    else if (command === 'dataset import')
      result = await service.importDataset(
        required(options, 'manifest'),
        required(options, 'artifact-root'),
      );
    else if (command === 'evidence import')
      result = await service.importEvidence(required(options, 'bundle'));
    else if (command === 'model lift') {
      const cutpoints = await optionalJson<string[]>(options, 'cutpoints', []);
      assert(
        Array.isArray(cutpoints) && cutpoints.every((x) => typeof x === 'string'),
        'CLI_USAGE',
        'Cutpoints must be a JSON string array',
      );
      result = await service.liftModel(
        required(options, 'evidence'),
        required(options, 'output'),
        cutpoints,
      );
    } else if (command === 'report export')
      result = await service.exportReport(required(options, 'run'), required(options, 'out'));
    else if (command === 'dataset collect') {
      const rows = await readJsonl<InputSample>(required(options, 'inputs')),
        policy = await readJson<ComparisonPolicy>(required(options, 'policy'));
      const completed = await foreground(service, () =>
        service.collectDataset(
          required(options, 'oracle'),
          rows,
          policy,
          integer(options, 'max-calls', 512),
        ),
      );
      result = completed.value;
      code = completed.code;
    } else if (command === 'ida analyze') {
      const request={file:required(options,'file'),queries:await readJson<IdaQuery[]>(required(options,'query')),...(options.timeout!==undefined?{timeout_ms:binaryInteger(options,'timeout',600000)}:{})};
      validateIdaAnalysisRequest(request);
      const completed=await foreground(service,()=>submitIdaAnalysis(service,request));result=completed.value;code=completed.code;
    } else if (command === 'binary trace') {
      const request: unknown = {
        file: required(options, 'file'),
        tool: await readJson<unknown>(required(options, 'config')),
        plan: await readJson<unknown>(required(options, 'plan')),
      };
      try {
        validateNativeTraceRequest(request);
      } catch (error) {
        if (error instanceof WirefitError && error.code === 'NATIVE_TRACE_REQUEST_INVALID')
          throw new WirefitError('CLI_USAGE', error.message, error.details);
        throw error;
      }
      const completed = await foreground(service, () => submitBinaryTrace(service, request));
      result = completed.value;
      code = completed.code;
    } else if (command === 'binary inspect' || command === 'binary unpack') {
      const file = required(options, 'file');
      assert(
        binaryText(file),
        'CLI_USAGE',
        '--file must be a nonempty path of at most 4096 characters without NUL',
      );
      if (command === 'binary unpack') required(options, 'config');
      const configured = await optionalJson<unknown>(options, 'config', undefined);
      const toolchain = configured === undefined ? undefined : binaryToolchain(configured);
      const common = {
        file,
        ...(toolchain !== undefined ? { toolchain } : {}),
        ...(options.timeout !== undefined
          ? { timeout_ms: binaryInteger(options, 'timeout', 600000) }
          : {}),
      };
      let completed: Awaited<ReturnType<typeof foreground>>;
      if (command === 'binary inspect')
        completed = await foreground(service, () => submitBinaryInspection(service, common));
      else {
        assert(
          required(options, 'backend') === 'unlicense',
          'CLI_USAGE',
          '--backend must be unlicense',
        );
        assert(toolchain !== undefined, 'CLI_USAGE', 'Required option --config');
        const request = {
          ...common,
          backend: 'unlicense' as const,
          toolchain,
          ...(options['target-timeout'] !== undefined
            ? { target_timeout_seconds: binaryInteger(options, 'target-timeout', 600) }
            : {}),
          ...(options['no-copy-dependencies'] === true ? { copy_dependencies: false } : {}),
        };
        completed = await foreground(service, () => submitBinaryUnpack(service, request));
      }
      result = completed.value;
      code = completed.code;
    } else if (command === 'evidence acquire') {
      const configured = await optionalJson<Record<string, unknown>>(options, 'config', {}),
        runtime = path.join(
          rootDir,
          '.upstream/rea-runtime/node_modules/rea-agents/scripts/rea.mjs',
        );
      assert(
        configured &&
          typeof configured === 'object' &&
          !Array.isArray(configured) &&
          Object.keys(configured).every((key) =>
            [
              'command',
              'args',
              'cwd',
              'env',
              'target',
              'provider',
              'functionAddress',
              'timeoutMs',
              'recoveryTimeoutMs',
            ].includes(key),
          ),
        'CLI_USAGE',
        'REA config contains unsupported fields',
      );
      validateReaOptions(configured);
      const command =
        typeof options.command === 'string'
          ? options.command
          : typeof configured.command === 'string'
            ? configured.command
            : process.execPath;
      const args = await optionalJson<string[]>(
        options,
        'args',
        Array.isArray(configured.args) ? (configured.args as string[]) : [runtime, '--mcp'],
      );
      assert(
        Array.isArray(args) && args.every((a) => typeof a === 'string'),
        'CLI_USAGE',
        'REA args must be a JSON string array',
      );
      const target =
        typeof options.target === 'string' ? path.resolve(options.target) : configured.target;
      const request = {
        ...configured,
        command,
        args,
        ...(target !== undefined ? { target } : {}),
        ...(options.provider ? { provider: options.provider } : {}),
        ...(options.procedure ? { functionAddress: options.procedure } : {}),
        ...(options.cwd ? { cwd: path.resolve(required(options, 'cwd')) } : {}),
        ...(options.timeout ? { timeoutMs: integer(options, 'timeout', 120000) } : {}),
      };
      validateReaOptions(request);
      const completed = await foreground(service, () =>
        service.acquireEvidence(request as Parameters<WirefitService['acquireEvidence']>[0]),
      );
      result = completed.value;
      code = completed.code;
    } else if (command === 'research run') {
      const directionId = required(options, 'direction');
      const { researchDirection } = await import('./research/index.js');
      assert(
        researchDirection(directionId) !== null,
        'CLI_USAGE',
        'Unknown research direction: ' + directionId,
      );
      const request = {
        schema_version: 1 as const,
        research_id: id('research'),
        direction_id: directionId,
        budget: resolveBudget(await optionalJson<Partial<Budget>>(options, 'budget', {})),
      };
      const completed = await foreground(service, () => service.submitResearch(request));
      result = completed.value;
      code = completed.code;
    } else {
      const request = await experiment(service, command, options);
      const completed = await foreground(service, () => service.submitExperiment(request));
      result = completed.value;
      code = completed.code;
    }
  } finally {
    await service.close();
  }
  json(result);
  return code;
}
export async function runCli(): Promise<void> {
  try {
    process.exitCode = await main();
  } catch (error) {
    json({
      error: errorRecord(error, 'cli'),
      ...(error instanceof WirefitError && error.details !== undefined
        ? { details: error.details }
        : {}),
    });
    process.exitCode = error instanceof WirefitError && error.code === 'CLI_USAGE' ? 2 : 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  await runCli();

