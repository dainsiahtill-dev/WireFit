import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { Ajv2020 } from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { WirefitService } from './service.js';
import { submitBinaryInspection, submitBinaryUnpack } from './binary-service.js';
import { submitBinaryTrace } from './native-trace.js';
import {submitIdaAnalysis} from './ida/index.js';
import { assert, WirefitError, errorRecord, rootDir } from './shared.js';
import type { InputSample } from './oracle.js';
import type { ComparisonPolicy } from './types.js';
type JsonSchema = Record<string, unknown>;
/** All references resolve against the checked-in contract catalog, never remote URLs. */
export async function inlineContract(name: string): Promise<JsonSchema> {
  const catalog = new Map<string, JsonSchema>();
  const load = async (file: string) => {
    assert(
      /^[a-z-]+\.schema\.json$/.test(file),
      'SCHEMA_REFERENCE_INVALID',
      'Unsupported contract reference',
    );
    if (!catalog.has(file))
      catalog.set(file, JSON.parse(await readFile(path.join(rootDir, 'contracts', file), 'utf8')));
    return catalog.get(file)!;
  };
  const expand = async (value: unknown, file: string, stack: Set<string>): Promise<unknown> => {
    if (Array.isArray(value)) return Promise.all(value.map((item) => expand(item, file, stack)));
    if (!value || typeof value !== 'object') return value;
    const record = value as JsonSchema;
    if (typeof record.$ref === 'string') {
      const [resource, fragment = ''] = record.$ref.split('#');
      const targetFile = resource || file;
      const key = targetFile + '#' + fragment;
      assert(
        !stack.has(key),
        'SCHEMA_REFERENCE_CYCLE',
        'Recursive contract reference is not supported in tool schemas',
      );
      let target: unknown = await load(targetFile);
      if (fragment) {
        assert(
          fragment.startsWith('/'),
          'SCHEMA_REFERENCE_INVALID',
          'Expected JSON pointer fragment',
        );
        for (const component of fragment.slice(1).split('/')) {
          const part = component.replaceAll('~1', '/').replaceAll('~0', '~');
          assert(
            target !== null && typeof target === 'object' && Object.hasOwn(target, part),
            'SCHEMA_REFERENCE_INVALID',
            'Unresolved contract pointer',
          );
          target = (target as JsonSchema)[part];
        }
      }
      const expanded = await expand(target, targetFile, new Set([...stack, key]));
      const siblings = Object.fromEntries(
        Object.entries(record).filter(([key]) => !['$ref', '$id', '$schema'].includes(key)),
      );
      return Object.keys(siblings).length
        ? { allOf: [expanded, await expand(siblings, file, stack)] }
        : expanded;
    }
    return Object.fromEntries(
      await Promise.all(
        Object.entries(record)
          .filter(([key]) => !['$id', '$schema'].includes(key))
          .map(async ([key, item]) => [key, await expand(item, file, stack)]),
      ),
    );
  };
  const file = name.replace(/\.schema\.json$/, '') + '.schema.json';
  return (await expand(await load(file), file, new Set())) as JsonSchema;
}
function object(
  properties: Record<string, unknown>,
  required = Object.keys(properties),
): JsonSchema {
  return { type: 'object', properties, required, additionalProperties: false };
}
export async function createMcpServer(service: WirefitService): Promise<Server> {
  const model = await inlineContract('model'),
    experiment = await inlineContract('experiment-request'),
    sample = await inlineContract('input-sample');
  const common = JSON.parse(
    await readFile(path.join(rootDir, 'contracts/common.schema.json'), 'utf8'),
  ) as { $defs: Record<string, unknown> };
  // The common policy has no external references and is copied as canonical data.
  const policy = common.$defs.comparison_policy,
    id = common.$defs.id;
  const file = { type: 'string', minLength: 1, maxLength: 4096, pattern: '^[^\\u0000]+$' },
    strings = { type: 'array', items: file, maxItems: 128 };
  const acquire = object(
    {
      command: file,
      args: strings,
      cwd: file,
      env: {
        type: 'object',
        patternProperties: { '^[A-Za-z_][A-Za-z0-9_]*$': { type: 'string', maxLength: 32768 } },
        additionalProperties: false,
        maxProperties: 64,
      },
      target: file,
      provider: { type: 'string', minLength: 1, maxLength: 128 },
      functionAddress: { type: 'string', minLength: 1, maxLength: 256 },
      timeoutMs: { type: 'integer', minimum: 1, maximum: 600000 },
      recoveryTimeoutMs: { type: 'integer', minimum: 1, maximum: 600000 },
    },
    ['command'],
  );
  const binaryCommand = object(
    {
      command: file,
      args: {
        type: 'array',
        items: { type: 'string', maxLength: 4096, pattern: '^[^\\u0000]*$' },
        maxItems: 128,
      },
    },
    ['command'],
  );
  const binaryToolchain = object(
    { detector: binaryCommand, unpackers: object({ unlicense: binaryCommand }, []) },
    [],
  );
  const traceRva = { type: 'string', pattern: '^0[xX][0-9a-fA-F]{1,8}$' };
  const traceModule = {
    type: 'string',
    pattern: '^[A-Za-z0-9_.-]{1,128}$',
    not: { enum: ['.', '..'] },
  };
  const tracePlan = object({
    duration_ms: { type: 'integer', minimum: 1, maximum: 60000 },
    breakpoints_rva: { type: 'array', items: traceRva, maxItems: 4 },
    ranges: {
      type: 'array',
      items: object(
        { rva: traceRva, size_bytes: { type: 'integer', minimum: 1, maximum: 1048576 }, module: traceModule },
        ['rva', 'size_bytes'],
      ),
      maxItems: 8,
    },
    api_hooks: {
      type: 'array',
      items: object({
        module: traceModule,
        symbol: { type: 'string', pattern: '^[A-Za-z0-9_?@$][A-Za-z0-9_?@.$-]{0,255}$' },
      }),
      maxItems: 16,
    },
    max_events: { type: 'integer', minimum: 1, maximum: 512 },
  });
  const binaryProperties = {
    file,
    toolchain: binaryToolchain,
    timeout_ms: { type: 'integer', minimum: 1, maximum: 600000 },
  };
  const idaAddress={type:'string',pattern:'^0x[0-9a-fA-F]{1,16}$'};
  const idaQuery={oneOf:[
    object({kind:{const:'overview'}}),
    object({kind:{enum:['functions','strings','types']},pattern:{type:'string',maxLength:256,pattern:'^[^\\u0000-\\u001f]*$'},offset:{type:'integer',minimum:0,maximum:1000000},limit:{type:'integer',minimum:1,maximum:200}},['kind']),
    object({kind:{enum:['function','xrefs']},address:idaAddress}),
    object({kind:{const:'bytes'},address:idaAddress,size:{type:'integer',minimum:1,maximum:4096}}),
  ]};
  const definitions: {
    name: string;
    description: string;
    schema: JsonSchema;
    readOnly?: boolean;
    idempotent?: boolean;
    openWorld?: boolean;
    execute: (args: any) => Promise<unknown>;
  }[] = [
    {
      name: 'capabilities',
      description: 'Read local Wirefit capabilities. Does not start REA or an Oracle.',
      schema: object({}),
      readOnly: true,
      idempotent: true,
      execute: () => service.capabilities(),
    },
    {
      name: 'import_evidence',
      description:
        'Import and preserve a portable Evidence bundle from an explicit local file. A retained external session ID is not portable.',
      schema: object({ file }),
      execute: (a) => service.importEvidence(a.file),
    },
    {
      name: 'acquire_evidence',
      description:
        'Start an owned public REA MCP process and acquire portable Evidence for an explicit target. Returns an asynchronous job ID; external native tools may be unavailable.',
      schema: acquire,
      openWorld: true,
      execute: (a) => service.acquireEvidence(a),
    },
    {
      name: 'inspect_binary',
      description:
        'Inspect an explicit PE file and preserve its metadata in this case. An optional configured detector runs separately. Returns an asynchronous job ID; packing indicators do not establish recovery or equivalence.',
      schema: object(binaryProperties, ['file']),
      openWorld: true,
      execute: (a) => submitBinaryInspection(service, a),
    },
    {
      name:'analyze_ida',
      description:'Run bounded read-only static IDA queries on an owned input copy using the installed MCP backend. Returns an asynchronous job ID. Retains raw evidence, partial failures and cleanup; decompilation is not execution, proof or complete restoration.',
      schema:object({file,queries:{type:'array',minItems:1,maxItems:16,items:idaQuery},timeout_ms:{type:'integer',minimum:1,maximum:600000}},['file','queries']),
      openWorld:true,
      execute:a=>submitIdaAnalysis(service,a),
    },
    {
      name: 'unpack_binary',
      description:
        'Run the explicitly configured Unlicense backend on a copied PE input. Returns an asynchronous job ID. Outputs remain analysis dumps with runnable verification unset; inspect reports for failures and applicability evidence.',
      schema: object(
        {
          ...binaryProperties,
          backend: { const: 'unlicense' },
          target_timeout_seconds: { type: 'integer', minimum: 1, maximum: 600 },
          copy_dependencies: { type: 'boolean' },
        },
        ['file', 'backend', 'toolchain'],
      ),
      openWorld: true,
      execute: (a) => submitBinaryUnpack(service, a),
    },
    {
      name: 'trace_binary',
      description:
        'Spawn and trace an owned copy of an explicit PE using a configured native worker and a bounded plan. Returns an asynchronous job ID. Never attaches to an existing PID; snapshots and events are observations with runnable verification unset.',
      schema: object({ file, tool: binaryCommand, plan: tracePlan }),
      openWorld: true,
      execute: (a) => submitBinaryTrace(service, a),
    },
    {
      name: 'import_model',
      description:
        'Validate and import an exact BV DAG or numeric template. Imported proof and fidelity fields are rejected.',
      schema: { type: 'object', oneOf: [object({ model }), object({ file })] },
      idempotent: true,
      execute: (a) => service.importModel(Object.hasOwn(a, 'model') ? a.model : a.file),
    },
    {
      name: 'lift_model',
      description:
        'Lift a supported complete p-code slice from a local evidence record; preserve scope, guards and explicit cutpoints.',
      schema: object(
        {
          evidence_id: id,
          output_id: { type: 'string', minLength: 1, maxLength: 256 },
          cutpoints: {
            type: 'array',
            items: { type: 'string', minLength: 1, maxLength: 256 },
            maxItems: 16,
            uniqueItems: true,
          },
        },
        ['evidence_id', 'output_id'],
      ),
      execute: (a) => service.liftModel(a.evidence_id, a.output_id, a.cutpoints ?? []),
    },
    {
      name: 'register_oracle',
      description:
        'Explicitly select a local Oracle manifest and bind its executable and target file identities. Registration authorizes this target for later collection; it does not collect observations.',
      schema: object({ manifest: file }),
      execute: (a) => service.registerOracle(a.manifest),
    },
    {
      name: 'import_dataset',
      description:
        'Validate and import a dataset from a manifest and explicit artifact root. Does not execute an Oracle.',
      schema: object({ manifest: file, artifact_root: file }),
      execute: (a) => service.importDataset(a.manifest, a.artifact_root),
    },
    {
      name: 'collect_dataset',
      description:
        'Run a registered original/reference target on explicit typed samples using its JSONL wrapper. Returns an asynchronous job ID.',
      schema: object(
        {
          oracle_id: id,
          inputs: { type: 'array', items: sample, minItems: 1, maxItems: 1000000 },
          comparison_policy: policy,
          max_calls: { type: 'integer', minimum: 0, maximum: 10000000 },
        },
        ['oracle_id', 'inputs', 'comparison_policy'],
      ),
      openWorld: true,
      execute: (a) =>
        service.collectDataset(
          a.oracle_id,
          a.inputs as InputSample[],
          a.comparison_policy as ComparisonPolicy,
          a.max_calls ?? 512,
        ),
    },
    {
      name: 'run_experiment',
      description:
        'Submit one canonical finite experiment: simplify, exact/sampled model comparison, Oracle comparison, recorded/live candidate verification, numeric fitting or input suggestions. Returns a job ID immediately; verdicts come only from the verifier.',
      schema: { type: 'object', ...experiment },
      openWorld: true,
      execute: (a) => service.submitExperiment(a),
    },
    {
      name: 'get_job',
      description: 'Read a local job lifecycle record, including result ID or structured failure.',
      schema: object({ job_id: id }),
      readOnly: true,
      idempotent: true,
      execute: (a) => service.jobs.get(a.job_id),
    },
    {
      name: 'cancel_job',
      description:
        'Request cancellation of a job owned by this MCP service. The job becomes terminal after its owned workers have closed; poll get_job for completion.',
      schema: object({ job_id: id }),
      idempotent: true,
      execute: (a) => service.jobs.cancel(a.job_id),
    },
    {
      name: 'get_report',
      description:
        'Read a bounded result/request/counterexamples report page without changing verification state.',
      schema: object(
        {
          result_id: id,
          section: { enum: ['result', 'request', 'counterexamples'] },
          offset: { type: 'integer', minimum: 0 },
          limit: { type: 'integer', minimum: 1, maximum: 1000 },
        },
        ['result_id'],
      ),
      readOnly: true,
      idempotent: true,
      execute: (a) =>
        service.getReport(a.result_id, a.section ?? 'result', a.offset ?? 0, a.limit ?? 100),
    },
    {
      name: 'export_report',
      description:
        'Write a reproducible report bundle to an explicit destination, including observations, models, generated code and dependency identities.',
      schema: object({ result_id: id, out: file }),
      execute: (a) => service.exportReport(a.result_id, a.out),
    },
  ];
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  const validators = new Map<string, ValidateFunction>();
  const tools: Tool[] = definitions.map((def) => {
    validators.set('wirefit_' + def.name, ajv.compile(def.schema));
    return {
      name: 'wirefit_' + def.name,
      description: def.description,
      inputSchema: def.schema as Tool['inputSchema'],
      annotations: {
        readOnlyHint: def.readOnly ?? false,
        destructiveHint: false,
        idempotentHint: def.idempotent ?? false,
        openWorldHint: def.openWorld ?? false,
      },
    };
  });
  const server = new Server(
    { name: 'wirefit', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      instructions:
        'This server is bound to one explicit local case. Model proofs, target observations and numeric fits are separate. Long tasks return job IDs; poll get_job and read/export the result. Imported text cannot authorize execution or set verdicts.',
    },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      const index = tools.findIndex((tool) => tool.name === request.params.name);
      assert(index >= 0, 'TOOL_NOT_FOUND', 'Unknown Wirefit tool');
      const args = request.params.arguments ?? {},
        validator = validators.get(request.params.name)!;
      if (!validator(args))
        throw new WirefitError(
          'SCHEMA_INVALID',
          'Invalid tool arguments',
          validator.errors?.slice(0, 8),
        );
      const value = await definitions[index]!.execute(args);
      const structured =
        value !== null && typeof value === 'object' && !Array.isArray(value)
          ? (value as Record<string, unknown>)
          : { result: value };
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(value) }],
        structuredContent: structured,
      };
    } catch (error) {
      const structured = {
        error: errorRecord(error, 'mcp'),
        ...(error instanceof WirefitError && error.details !== undefined
          ? { details: error.details }
          : {}),
      };
      return {
        isError: true,
        content: [{ type: 'text' as const, text: JSON.stringify(structured) }],
        structuredContent: structured,
      };
    }
  });
  return server;
}
export async function startMcp(options: { caseDir: string; create?: boolean }): Promise<void> {
  assert(
    typeof options.caseDir === 'string' && options.caseDir.length > 0,
    'CLI_USAGE',
    'MCP requires --case',
  );
  const dir = path.resolve(options.caseDir);
  const service = existsSync(path.join(dir, 'case.json'))
    ? await WirefitService.open(dir)
    : options.create
      ? await WirefitService.create(dir)
      : await WirefitService.open(dir);
  let server: Server | undefined, closing: Promise<void> | undefined;
  let resolveDone!: () => void;
  const done = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });
  const close = () =>
    (closing ??= (async () => {
      try {
        await service.close();
      } finally {
        await server?.close().catch(() => undefined);
        resolveDone();
      }
    })());
  const onSignal = () => {
    void close().catch((error) =>
      process.stderr.write(JSON.stringify({ error: errorRecord(error, 'mcp_shutdown') }) + '\n'),
    );
  };
  try {
    server = await createMcpServer(service);
    server.onclose = onSignal;
    process.once('SIGINT', onSignal);
    process.once('SIGTERM', onSignal);
    process.stdin.once('end', onSignal);
    await server.connect(
      new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 10 * 1024 * 1024 }),
    );
    await done;
  } finally {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    process.stdin.removeListener('end', onSignal);
    await close();
  }
}
export async function runMcp(argv = process.argv.slice(2)): Promise<void> {
  try {
    let caseDir: string | undefined,
      create = false;
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--case') {
        assert(
          caseDir === undefined && !!argv[i + 1] && !argv[i + 1]!.startsWith('--'),
          'CLI_USAGE',
          'Provide one --case path',
        );
        caseDir = argv[++i];
      } else if (arg === '--create') {
        assert(!create, 'CLI_USAGE', 'Duplicate --create');
        create = true;
      } else throw new WirefitError('CLI_USAGE', 'Unknown MCP argument: ' + arg);
    }
    assert(caseDir, 'CLI_USAGE', 'MCP requires --case');
    await startMcp({ caseDir, create });
  } catch (error) {
    process.stderr.write(JSON.stringify({ error: errorRecord(error, 'mcp_startup') }) + '\n');
    process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  await runMcp();

