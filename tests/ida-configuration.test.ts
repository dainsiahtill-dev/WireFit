import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { loadIdaConfiguration, idaCapabilities } from '../src/ida/index.js';
import { resolveIdaSourceScope } from '../src/ida/scope.js';
import { WirefitService } from '../src/service.js';
import { snapshot, putSnapshot } from '../src/binary-files.js';
import { verifyConfiguredIdaProbe } from '../src/ida/probe.js';
const temporary: string[] = [];
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
afterEach(async () => {
  for (const root of temporary.splice(0)) {
    expect(path.resolve(root).startsWith(path.resolve(tmpdir()) + path.sep + 'wirefit-ida-config-')).toBe(
      true,
    );
    await rm(root, { recursive: true, force: true });
  }
});
async function setup() {
  const root = await mkdtemp(path.join(tmpdir(), 'wirefit-ida-config-'));
  temporary.push(root);
  await mkdir(path.join(root, '.local'));
  return root;
}
const config = (command: string) => ({
  schema_version: 1,
  command,
  args: ['owned.py', '--input', '{input}', '--database', '{database}'],
  provider: { version: '9.3', server: 'ida-pro-mcp', revision: 'a'.repeat(40) },
  lifecycle: 'owned-stdio',
});
async function verified(root: string) {
  const executable = path.join(root, 'python.exe'),
    wrapper = path.join(root, 'owned.py'),
    native = path.join(root, 'ida');
  const packageFile = path.join(root, 'site-packages/ida_pro_mcp/api.py');
  const files = [
    executable,
    wrapper,
    packageFile,
    path.join(root, 'site-packages/idapro/__init__.py'),
    path.join(native, 'idalib.dll'),
    path.join(native, 'ida.dll'),
    path.join(native, 'plugins/hexx64.dll'),
  ];
  const hashes: Record<string, string> = {};
  for (const file of files) {
    const contents = file.endsWith('__init__.py') ? '' : 'fixture runtime identity';
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, contents, 'utf8');
    hashes[file] = digest(contents);
  }
  const sample = path.join(root, 'fixture.bin');
  await writeFile(sample, 'static sample', 'utf8');
  const receipt = path.join(root, 'probe.json'),
    manifest = path.join(root, 'manifest.json');
  const selected = {
    ...config(executable),
    args: [wrapper, '--input', '{input}', '--database', '{database}'],
    env: { IDADIR: native },
    probe_receipt: receipt,
  };
  const configurationPath = path.join(root, '.local/ida-mcp.json');
  await writeFile(configurationPath, JSON.stringify(selected), 'utf8');
  hashes[configurationPath] = digest(await readFile(configurationPath));
  await writeFile(manifest, JSON.stringify({ revision: 'a'.repeat(40), sha256: hashes }), 'utf8');
  const proof = {
    status: 'completed',
    revision: 'a'.repeat(40),
    command_sha256: hashes[executable],
    wrapper_sha256: hashes[wrapper],
    configuration_sha256: hashes[configurationPath],
    runtime_manifest: manifest,
    runtime_manifest_sha256: digest(await readFile(manifest)),
    native_initialized: true,
    mcp_handshake: true,
    identity_verified: true,
    fixture: { disassembly: true, decompilation: true },
    checked_at: '2026-10-20T10:00:00.000Z',
    samples: [
      {
        id: 'fixture',
        label: 'Owned fixture',
        file: sample,
        sha256: digest('static sample'),
        description: 'Owned static fixture',
        address: '0x1000',
      },
    ],
  };
  await writeFile(receipt, JSON.stringify(proof), 'utf8');
  return { executable, wrapper, packageFile, sample, configurationPath, receipt, proof };
}
describe('IDA local capability evidence', () => {
  it('verifies an explicitly selected runtime in its own root and rejects changed launch arguments', async () => {
    const root = await setup();
    await verified(root);
    const selected = (await loadIdaConfiguration(root))!;
    expect((await verifyConfiguredIdaProbe(selected)).files_verified).toBe(8);
    await expect(
      verifyConfiguredIdaProbe({ ...selected, args: [...selected.args, '--different-launch'] }),
    ).rejects.toThrow();
  });
  it('persists verified derived-window context as host-owned evidence', async () => {
    const root = await setup(),
      probe = await verified(root);
    const provenance = path.join(root, 'provenance.json');
    const bytes = JSON.stringify({
      kind: 'exact_dump_window',
      size_bytes: 4096,
      original_target_fidelity: 'unknown',
    });
    await writeFile(provenance, bytes, 'utf8');
    const proof = JSON.parse(await readFile(probe.receipt, 'utf8'));
    Object.assign(proof.samples[0], {
      scope_kind: 'derived_window',
      provenance: { file: provenance, sha256: digest(bytes) },
    });
    await writeFile(probe.receipt, JSON.stringify(proof), 'utf8');
    const service = await WirefitService.create(path.join(root, 'case'));
    try {
      const source = await putSnapshot(service, await snapshot(probe.sample));
      const context = await resolveIdaSourceScope(service, source, root);
      expect(context.scope).toMatchObject({
        kind: 'derived_window',
        label: 'Owned fixture',
        description: 'Owned static fixture',
      });
      expect(context.scope.provenance_artifact?.sha256).toBe(digest(bytes));
      expect(context.artifacts).toContainEqual(context.scope.provenance_artifact);
      expect((await service.store.readArtifact(context.scope.provenance_artifact!)).toString('utf8')).toBe(
        bytes,
      );
    } finally {
      await service.close();
    }
  });
  it('reports an absent local runtime without launching a process', async () => {
    const root = await setup();
    expect(await loadIdaConfiguration(root)).toBeUndefined();
    expect(await idaCapabilities(root)).toMatchObject({
      configured: false,
      installed: false,
      status: 'not_configured',
      native_execution: false,
    });
  });
  it('does not call a present executable native availability', async () => {
    const root = await setup();
    await writeFile(path.join(root, '.local/ida-mcp.json'), JSON.stringify(config(process.execPath)), 'utf8');
    expect(await idaCapabilities(root)).toMatchObject({
      configured: true,
      installed: true,
      status: 'not_probed',
    });
  });
  it('rejects administrator configuration that cannot isolate its input and IDB', async () => {
    const root = await setup();
    await writeFile(
      path.join(root, '.local/ida-mcp.json'),
      JSON.stringify({ ...config(process.execPath), args: ['server.py'] }),
      'utf8',
    );
    await expect(loadIdaConfiguration(root)).rejects.toThrow();
    expect(await idaCapabilities(root)).toMatchObject({ status: 'invalid_configuration' });
  });
  it('requires matching executable and revision before trusting a persisted real probe', async () => {
    const root = await setup(),
      probe = await verified(root);
    expect(await idaCapabilities(root)).toMatchObject({ status: 'verified' });
    await writeFile(probe.executable, 'changed executable identity', 'utf8');
    expect(await idaCapabilities(root)).toMatchObject({ status: 'probe_failed' });
  });
  it.each(['wrapper', 'packageFile', 'configurationPath'] as const)(
    'invalidates a persisted probe when %s changes',
    async (key) => {
      const root = await setup(),
        probe = await verified(root);
      expect(await idaCapabilities(root)).toMatchObject({ status: 'verified' });
      if (key === 'configurationPath') {
        const changed = JSON.parse(await readFile(probe.configurationPath, 'utf8'));
        changed.env.IDADIR = path.join(root, 'different-ida');
        await writeFile(probe.configurationPath, JSON.stringify(changed), 'utf8');
      } else await writeFile(probe[key], 'changed runtime identity', 'utf8');
      expect(await idaCapabilities(root)).toMatchObject({ status: 'probe_failed' });
    },
  );
  it('exposes only hash-verified samples from a verified receipt', async () => {
    const root = await setup(),
      probe = await verified(root);
    expect((await idaCapabilities(root)).samples).toEqual([
      {
        id: 'fixture',
        label: 'Owned fixture',
        file: probe.sample,
        sha256: digest('static sample'),
        description: 'Owned static fixture',
        address: '0x1000',
      },
    ]);
    await writeFile(probe.sample, 'changed input', 'utf8');
    expect((await idaCapabilities(root)).samples).toEqual([]);
  });
});
