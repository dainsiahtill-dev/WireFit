import { it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { CaseStore } from '../src/store.js';
const root = path.resolve('.');
const local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
const execute = promisify(execFile);
async function cli(...args: string[]) {
  let result;
  try {
    result = await execute(runtime, ['--import', 'tsx', path.join(root, 'src/cli.ts'), ...args], {
      cwd: root,
    });
  } catch (error) {
    const detail = error as Error & { stdout?: string };
    detail.message += ' stdout=' + detail.stdout;
    throw error;
  }
  return { data: JSON.parse(result.stdout), stderr: result.stderr };
}
it('doctor works offline without a case or REA process and wrappers select the pinned runtime', async () => {
  const { data } = await cli('doctor', '--json');
  expect(data.product).toBe('Wirefit');
  expect(data.runtime.node).toMatch(/^v24\./);
  const wrapper = await execute(process.execPath, [
    path.join(root, 'apps/cli/bin/wirefit.js'),
    '--help',
  ]);
  expect(wrapper.stdout).toContain('wirefit');
});
it('runs real foreground case import evaluate compare and read-only job inspection', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-')),
    caseDir = path.join(dir, 'case');
  try {
    expect((await cli('case', 'create', '--dir', caseDir)).data.case_dir).toBe(caseDir);
    const left = (
      await cli('model', 'import', '--case', caseDir, '--file', 'examples/model.mba-u8.json')
    ).data.model_id;
    const right = (
      await cli('model', 'import', '--case', caseDir, '--file', 'examples/model.add-u8.json')
    ).data.model_id;
    const input = path.join(dir, 'inputs.json');
    await writeFile(
      input,
      JSON.stringify({
        a: { kind: 'bv', width: 8, bits: '0xfa' },
        b: { kind: 'bv', width: 8, bits: '0x0a' },
      }),
      'utf8',
    );
    expect(
      (await cli('model', 'evaluate', '--case', caseDir, '--model', left, '--inputs', input)).data
        .outputs.result.bits,
    ).toBe('0x04');
    const compared = await cli('compare', '--case', caseDir, '--left', left, '--right', right);
    expect(compared.data.job.status).toBe('completed');
    expect(compared.data.result.model_check.status).toBe('proved');
    expect(compared.stderr).toContain('job_submitted');
    const renamed = JSON.parse(await readFile('examples/model.add-u8.json', 'utf8'));
    renamed.model_id = 'cli_renamed';
    renamed.inputs[0].id = 'x';
    renamed.inputs[1].id = 'y';
    for (const node of renamed.nodes)
      node.args = node.args.map((id: string) => (id === 'a' ? 'x' : id === 'b' ? 'y' : id));
    renamed.outputs[0].id = 'out';
    const renamedFile = path.join(dir, 'renamed.json');
    await writeFile(renamedFile, JSON.stringify(renamed), 'utf8');
    await cli('model', 'import', '--case', caseDir, '--file', renamedFile);
    const mappingFile = path.join(dir, 'mapping.json');
    await writeFile(
      mappingFile,
      JSON.stringify({
        inputs: [
          { left: 'a', right: 'x' },
          { left: 'b', right: 'y' },
        ],
        outputs: [{ left: 'result', right: 'out' }],
      }),
      'utf8',
    );
    expect(
      (
        await cli(
          'compare',
          '--case',
          caseDir,
          '--left',
          left,
          '--right',
          'cli_renamed',
          '--mapping',
          mappingFile,
        )
      ).data.result.model_check.status,
    ).toBe('proved');
    const out = path.join(dir, 'export');
    const exported = (
      await cli(
        'report',
        'export',
        '--case',
        caseDir,
        '--run',
        compared.data.result.result_id,
        '--out',
        out,
      )
    ).data;
    expect(exported.output_directory).toBe(out);
    expect(JSON.parse(await readFile(path.join(out, 'manifest.json'), 'utf8')).run_id).toBe(
      compared.data.result.result_id,
    );
    const writer = await CaseStore.open(caseDir);
    try {
      const jobs = (await cli('jobs', '--case', caseDir)).data;
      expect(jobs.jobs.some((j: any) => j.job_id === compared.data.job.job_id)).toBe(true);
      expect(
        (await cli('job', 'show', '--case', caseDir, '--job', compared.data.job.job_id)).data
          .status,
      ).toBe('completed');
    } finally {
      await writer.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it('rejects mutually exclusive compare forms and unknown or repeated flags', async () => {
  await expect(
    cli('compare', '--case', 'unused', '--left', 'x', '--right-oracle', 'y'),
  ).rejects.toMatchObject({ code: 2 });
  await expect(cli('doctor', '--unknown')).rejects.toMatchObject({ code: 2 });
  await expect(cli('doctor', '--json', '--json')).rejects.toMatchObject({ code: 2 });
});
import { sha256 } from '../src/shared.js';
it('runs actual registered Oracle collection and paired Oracle comparison from external JSONL', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-oracle-')),
    caseDir = path.join(dir, 'case');
  try {
    await cli('case', 'create', '--dir', caseDir);
    for (const [name, delta] of [
      ['left', 0],
      ['right', 1],
    ] as const) {
      const target = path.join(dir, name + '.cjs');
      const text = `let text='';process.stdin.setEncoding('utf8');process.stdin.on('data',d=>text+=d);process.stdin.on('end',()=>{const q=JSON.parse(text);const bits='0x'+BigInt.asUintN(64,BigInt(q.inputs.x.bits)+${delta}n).toString(16).padStart(16,'0');console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:'ok',outputs:{result:{kind:'bv',width:64,bits}}}));});`;
      await writeFile(target, text, 'utf8');
      const manifest = {
        schema_version: 1,
        oracle_id: 'cli_' + name,
        kind: 'process_jsonl',
        source_kind: 'reference_fixture',
        argv: [runtime, target],
        cwd: '.',
        signature: {
          inputs: [{ id: 'x', type: { kind: 'bv', width: 64 } }],
          outputs: [{ id: 'result', type: { kind: 'bv', width: 64 } }],
        },
        domain: { constraints: [] },
        target_files: [{ path: name + '.cjs', sha256: sha256(text), role: 'target' }],
        protocol_version: 1,
        reset_strategy: 'fresh_process',
        request_timeout_ms: 2000,
        batch_timeout_ms: 10000,
        max_stdout_line_bytes: 65536,
        max_stderr_bytes: 8192,
        allowed_env_keys: [],
        notes: 'Independent source-owned CLI target fixture',
      };
      const file = path.join(dir, name + '.json');
      await writeFile(file, JSON.stringify(manifest), 'utf8');
      expect(
        (await cli('oracle', 'register', '--case', caseDir, '--manifest', file)).data.oracle_id,
      ).toBe('cli_' + name);
    }
    const inputs = path.join(dir, 'inputs.jsonl'),
      policy = path.join(dir, 'policy.json');
    await writeFile(
      inputs,
      [0, 1, 2]
        .map((n, i) =>
          JSON.stringify({
            sample_id: 'q' + i,
            split: ['train', 'validation', 'holdout'][i],
            inputs: {
              x: { kind: 'bv', width: 64, bits: '0x' + BigInt(n).toString(16).padStart(16, '0') },
            },
          }),
        )
        .join('\n') + '\n',
      'utf8',
    );
    await writeFile(policy, JSON.stringify({ kind: 'exact-bv' }), 'utf8');
    const collection = (
      await cli(
        'dataset',
        'collect',
        '--case',
        caseDir,
        '--oracle',
        'cli_left',
        '--inputs',
        inputs,
        '--policy',
        policy,
        '--max-calls',
        '3',
      )
    ).data;
    expect(collection.job.status).toBe('completed');
    expect(collection.result.actual_oracle_calls).toBe(3);
    const compared = (
      await cli(
        'compare',
        '--case',
        caseDir,
        '--left-oracle',
        'cli_left',
        '--right-oracle',
        'cli_right',
        '--inputs',
        inputs,
        '--policy',
        policy,
      )
    ).data;
    expect(compared.result.model_check.status).toBe('not_run');
    expect(compared.result.target_validation.status).toBe('mismatch');
    expect(compared.result.target_validation.counts).toMatchObject({
      planned: 3,
      completed: 3,
      mismatched: 3,
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it('exposes a proved simplified candidate and a fitted numeric candidate without target promotion', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-candidates-')),
    caseDir = path.join(dir, 'case');
  try {
    await cli('case', 'create', '--dir', caseDir);
    await cli('model', 'import', '--case', caseDir, '--file', 'examples/model.mba-u8.json');
    const simplified = (await cli('model', 'simplify', '--case', caseDir, '--model', 'mba_u8'))
      .data;
    expect(simplified.result.model_check.status).toBe('proved');
    expect(simplified.candidate_model_id).toMatch(/^model_/);
    const fittedModel = (
      await cli(
        'model',
        'import',
        '--case',
        caseDir,
        '--file',
        'examples/model.affine-initial.json',
      )
    ).data;
    const manifest = JSON.parse(await readFile('examples/dataset.numeric-expected.json', 'utf8'));
    manifest.dataset_id = 'cli_affine_expected';
    manifest.source.source_id = 'cli_affine_source';
    manifest.source.source_identity_sha256 = sha256(
      'independent source-owned y=f32(2*x+1) fixture',
    );
    const inputsText = await readFile('examples/numeric-inputs.jsonl', 'utf8');
    await writeFile(path.join(dir, 'inputs.jsonl'), inputsText, 'utf8');
    manifest.sampling_plan.inputs_artifact = {
      sha256: sha256(inputsText),
      relative_path: 'inputs.jsonl',
      media_type: 'application/x-ndjson',
      size_bytes: Buffer.byteLength(inputsText, 'utf8'),
    };
    for (const split of ['train', 'validation', 'holdout']) {
      const text = await readFile('examples/numeric-' + split + '.jsonl', 'utf8');
      const rows = text
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      for (const row of rows) {
        const view = new DataView(new ArrayBuffer(4));
        view.setUint32(0, parseInt(row.inputs.x.bits.slice(2), 16));
        const x = view.getFloat32(0);
        view.setFloat32(0, Math.fround(2 * x + 1));
        row.outputs.result.bits = '0x' + view.getUint32(0).toString(16).padStart(8, '0');
        row.source_id = manifest.source.source_id;
        row.source_identity_sha256 = manifest.source.source_identity_sha256;
      }
      const bytes = rows.map((row) => JSON.stringify(row)).join('\n') + '\n';
      await writeFile(path.join(dir, split + '.jsonl'), bytes, 'utf8');
      manifest.splits[split].artifact = {
        sha256: sha256(bytes),
        relative_path: split + '.jsonl',
        media_type: 'application/x-ndjson',
        size_bytes: Buffer.byteLength(bytes, 'utf8'),
      };
    }
    const file = path.join(dir, 'dataset.json');
    await writeFile(file, JSON.stringify(manifest), 'utf8');
    await cli('dataset', 'import', '--case', caseDir, '--manifest', file, '--artifact-root', dir);
    const fitted = (
      await cli(
        'model',
        'fit',
        '--case',
        caseDir,
        '--dataset',
        'cli_affine_expected',
        '--template-model',
        fittedModel.model_id,
        '--backend',
        'analytic_baseline',
      )
    ).data;
    expect(fitted.job.status).toBe('completed');
    expect(fitted.result.fit.status).toBe('fitted');
    expect(fitted.candidate_model_id).toMatch(/^model_/);
    expect(fitted.result.target_validation.status).not.toBe('matched');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it('requires an explicit output selection when signatures have different output sets', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-mapping-')),
    caseDir = path.join(dir, 'case');
  try {
    await cli('case', 'create', '--dir', caseDir);
    await cli('model', 'import', '--case', caseDir, '--file', 'examples/model.add-u8.json');
    const model = JSON.parse(await readFile('examples/model.add-u8.json', 'utf8'));
    model.model_id = 'extra_output';
    model.outputs.push({ ...model.outputs[0], id: 'extra' });
    const file = path.join(dir, 'extra.json');
    await writeFile(file, JSON.stringify(model), 'utf8');
    await cli('model', 'import', '--case', caseDir, '--file', file);
    await expect(
      cli('compare', '--case', caseDir, '--left', 'add_u8', '--right', 'extra_output'),
    ).rejects.toMatchObject({ code: 1 });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it('rejects malformed acquisition config before it can start an external process', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-config-')),
    caseDir = path.join(dir, 'case');
  try {
    await cli('case', 'create', '--dir', caseDir);
    const file = path.join(dir, 'invalid.json');
    await writeFile(file, JSON.stringify({ command: 42, args: ['-e', 'process.exit(0)'] }), 'utf8');
    await expect(
      cli('evidence', 'acquire', '--case', caseDir, '--config', file),
    ).rejects.toMatchObject({ code: 2 });
    expect((await cli('jobs', '--case', caseDir)).data.jobs).toEqual([]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 15000);
