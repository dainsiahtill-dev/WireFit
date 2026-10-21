import { it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { defaultBudget } from '../src/shared.js';
const root = path.resolve('.'),
  local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe'),
  runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
async function setup() {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-mcp-'));
  const client = new Client({ name: 'wirefit-test', version: '1.0' });
  const transport = new StdioClientTransport({
    command: runtime,
    args: [
      '--import',
      'tsx',
      path.join(root, 'src/mcp.ts'),
      '--case',
      path.join(dir, 'case'),
      '--create',
    ],
    stderr: 'pipe',
  });
  await client.connect(transport);
  return { dir, client };
}
async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name: 'wirefit_' + name, arguments: args });
  return result;
}
async function wait(client: Client, id: string) {
  for (let i = 0; i < 600; i++) {
    const result = await call(client, 'get_job', { job_id: id });
    const job = result.structuredContent as any;
    if (['completed', 'failed', 'cancelled', 'interrupted'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw Error('Job poll deadline');
}
it('advertises the strict tool catalog with bounded IDA analysis, the canonical experiment union and the research tools', async () => {
  const { dir, client } = await setup();
  try {
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(19);
    const ida=tools.find(t=>t.name==='wirefit_analyze_ida');expect(ida).toBeDefined();
    const invalidIda=await call(client,'analyze_ida',{file:'sample.exe',queries:[{kind:'py_eval',code:'bad'}]});
    expect(invalidIda.isError).toBe(true);expect((invalidIda.structuredContent as any).error.code).toBe('SCHEMA_INVALID');
    expect(tools.every((t) => t.name.startsWith('wirefit_'))).toBe(true);
    const tool = tools.find((t) => t.name === 'wirefit_run_experiment')!;
    const canonical = JSON.parse(
      await readFile('contracts/experiment-request.schema.json', 'utf8'),
    );
    expect(tool.inputSchema.oneOf).toHaveLength(canonical.oneOf.length);
    expect(JSON.stringify(tool.inputSchema)).not.toContain('"$ref"');
    const denied = await call(client, 'run_experiment', {
      schema_version: 1,
      experiment_id: 'bad',
      operation: 'simplify',
      reference_model_id: 'x',
      budget: defaultBudget,
      domain: { constraints: [] },
      search: { grammar: ['bv_add'], constants: [], objective: 'node_count' },
      verdict: 'proved',
    });
    expect(denied.isError).toBe(true);
    expect((denied.structuredContent as any).error.code).toBe('SCHEMA_INVALID');
  } finally {
    await client.close();
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it('runs actual asynchronous Z3 jobs through the official MCP client and fetches counterexamples', async () => {
  const { dir, client } = await setup();
  try {
    for (const name of ['add-u8', 'add-u8-wrong'])
      expect(
        (
          await call(client, 'import_model', {
            model: JSON.parse(await readFile(`examples/model.${name}.json`, 'utf8')),
          })
        ).isError,
      ).not.toBe(true);
    const req = {
      schema_version: 1,
      experiment_id: 'mcp_compare',
      operation: 'compare_models',
      left_model_id: 'add_u8',
      right_model_id: 'add_u8_wrong',
      budget: defaultBudget,
      domain: { constraints: [] },
      mapping: {
        inputs: [
          { left: 'a', right: 'a' },
          { left: 'b', right: 'b' },
        ],
        outputs: [{ left: 'result', right: 'result' }],
      },
      mode: 'exact_bv',
    };
    const submitted = await call(client, 'run_experiment', req);
    expect(submitted.isError).not.toBe(true);
    const job = await wait(client, (submitted.structuredContent as any).job_id);
    expect(job.status).toBe('completed');
    const report = await call(client, 'get_report', { result_id: job.result_id });
    expect((report.structuredContent as any).data.model_check.status).toBe('refuted');
    const counterexamples = await call(client, 'get_report', {
      result_id: job.result_id,
      section: 'counterexamples',
    });
    expect(counterexamples.isError).not.toBe(true);
    expect(JSON.stringify(counterexamples.structuredContent)).toContain('bits');
    const second = await call(client, 'run_experiment', { ...req, experiment_id: 'mcp_cancel' });
    const id = (second.structuredContent as any).job_id;
    await call(client, 'cancel_job', { job_id: id });
    expect((await wait(client, id)).status).toBe('cancelled');
  } finally {
    await client.close();
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);

