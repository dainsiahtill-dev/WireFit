import { it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createEvidence } from '../vendor/rea/src/domain/evidence.js';
import { createEvidenceBundle } from '../vendor/rea/src/domain/evidenceBundle.js';
const root = path.resolve('.'),
  local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe'),
  runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
const execute = promisify(execFile);
async function cli(...args: string[]) {
  const { stdout } = await execute(
    runtime,
    ['--import', 'tsx', path.join(root, 'src/cli.ts'), ...args],
    { cwd: root },
  );
  return JSON.parse(stdout);
}
it('imports and lifts a synthetic authenticated complete scalar bundle while retaining its unknown guard', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-evidence-')),
    caseDir = path.join(dir, 'case');
  try {
    await cli('case', 'create', '--dir', caseDir);
    const variable = {
      kind: 'register',
      size_bytes: 8,
      location: 'register:0x0',
      constant_hex: null,
    };
    const constant = { kind: 'constant', size_bytes: 8, location: null, constant_hex: '1' };
    const evidence = createEvidence(
      { path: '/synthetic/cli', sha256: 'b'.repeat(64), format: 'elf', architecture: 'x86_64' },
      { id: 'ghidra', name: 'Ghidra', version: '12.1.4' },
      {
        operation: 'analyze_function',
        parameters: {},
        result: {
          native_value_flow: {
            available: true,
            provenance: 'ghidra-high-pcode',
            operations: [
              {
                id: 'a',
                address: '0x401000',
                sequence: 0,
                opcode: 'INT_ADD',
                is_dead: false,
                block_membership: 'member',
                inputs: [variable, constant],
                output: variable,
              },
            ],
            def_use: [],
            parameters: [{ ordinal: 0, name: 'x', data_type: 'uint64_t' }],
            parameter_uses: [{ ordinal: 0, use: 'a', input_index: 0 }],
            effects: [],
            truncated: false,
            omitted_operations_lower_bound: 0,
            known_omitted_inputs: 0,
            known_omitted_edges: 0,
            limitations: ['Synthetic CLI protocol fixture; not a native provider execution.'],
          },
        },
      },
    );
    const file = path.join(dir, 'bundle.json');
    await writeFile(file, JSON.stringify(createEvidenceBundle([evidence])), 'utf8');
    const imported = await cli('evidence', 'import', '--case', caseDir, '--bundle', file);
    expect(imported.status).toBe('supported');
    const lifted = await cli(
      'model',
      'lift',
      '--case',
      caseDir,
      '--evidence',
      imported.record_ids[0],
      '--output',
      'a',
    );
    expect(lifted.scope.execution_guard.kind).toBe('unknown');
    expect(lifted.target_replay_eligible).toBe(false);
    const inputs = path.join(dir, 'inputs.json');
    await writeFile(
      inputs,
      JSON.stringify({ p0: { kind: 'bv', width: 64, bits: '0xffffffffffffffff' } }),
      'utf8',
    );
    expect(
      (
        await cli(
          'model',
          'evaluate',
          '--case',
          caseDir,
          '--model',
          lifted.model_id,
          '--inputs',
          inputs,
        )
      ).outputs.y.bits,
    ).toBe('0x0000000000000000');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
it.skipIf(
  !existsSync(path.join(root, '.upstream/rea-runtime/node_modules/rea-agents/scripts/rea.mjs')),
)(
  'runs the actual installed public REA discovery/export lifecycle through the CLI',
  async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'wirefit-cli-rea-')),
      caseDir = path.join(dir, 'case');
    try {
      await cli('case', 'create', '--dir', caseDir);
      const acquired = await cli('evidence', 'acquire', '--case', caseDir, '--timeout', '30000');
      expect(acquired.job.status).toBe('completed');
      expect(acquired.result.cleanup.closed).toBe(true);
      expect(acquired.result.saved.status).toBe('supported');
      expect(acquired.result.saved.record_ids).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
  60000,
);
