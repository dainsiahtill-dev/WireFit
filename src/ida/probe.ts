import path from 'node:path';
import { snapshot } from '../binary-files.js';
import { assert, canonical } from '../shared.js';
import { boundedText, dataObject } from './validation.js';
import type { IdaConfiguration, IdaSample } from './types.js';
import { fingerprintIdaFile } from './files.js';

const DIGEST = /^[a-f0-9]{64}$/;
const CODE = 'IDA_PROBE_IDENTITY_MISMATCH';
function key(file: string): string {
  return path.resolve(file).replaceAll('\\', '/').toLowerCase();
}
/** Check actual launch, installed adapter code and IDA libraries against the observed probe. */
export async function verifyIdaRuntime(
  config: IdaConfiguration,
  configurationPath: string | undefined,
  probe: Record<string, unknown>,
): Promise<{ manifest_sha256: string; files_verified: number }> {
  boundedText(probe.runtime_manifest, 4096, 'Runtime manifest', false, CODE);
  assert(
    path.isAbsolute(probe.runtime_manifest) &&
      typeof probe.runtime_manifest_sha256 === 'string' &&
      DIGEST.test(probe.runtime_manifest_sha256),
    CODE,
    'Native probe omitted its runtime manifest identity',
  );
  const manifestBytes = await snapshot(probe.runtime_manifest, 1024 * 1024);
  assert(
    manifestBytes.sha256 === probe.runtime_manifest_sha256,
    CODE,
    'Native runtime manifest identity changed',
  );
  const manifest = dataObject(
    JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes.bytes)),
    ['revision', 'sha256'],
    'Runtime manifest',
    CODE,
  );
  assert(
    manifest.revision === config.provider.revision &&
      manifest.sha256 !== null &&
      typeof manifest.sha256 === 'object' &&
      !Array.isArray(manifest.sha256),
    CODE,
    'Native runtime revision or file identities are missing',
  );
  const entries = Object.entries(manifest.sha256);
  assert(
    entries.length >= 7 && entries.length <= 256,
    CODE,
    'Native runtime manifest exceeds its file budget',
  );
  const candidates = entries.filter(
    ([file, digest]) => digest === probe.configuration_sha256 && path.basename(file) === 'ida-mcp.json',
  );
  if (configurationPath === undefined) {
    assert(candidates.length === 1, CODE, 'Native probe did not identify one administrator configuration');
    configurationPath = candidates[0]![0];
  }
  const current = await snapshot(configurationPath, 64 * 1024);
  assert(
    probe.configuration_sha256 === current.sha256,
    CODE,
    'IDA launch configuration changed since its native probe',
  );
  const declared = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(current.bytes));
  assert(
    canonical(declared) === canonical(config),
    CODE,
    'Selected runtime arguments or environment differ from the probed administrator configuration',
  );
  const fingerprints = new Map<string, string>();
  let total = 0;
  for (const [file, digest] of entries) {
    assert(
      path.isAbsolute(file) && file.length <= 4096 && typeof digest === 'string' && DIGEST.test(digest),
      CODE,
      'Runtime fingerprint is invalid',
    );
    const normalized = key(file);
    assert(!fingerprints.has(normalized), CODE, 'Runtime fingerprint paths collide');
    const observed = await fingerprintIdaFile(file);
    total += observed.size_bytes;
    assert(
      total <= 512 * 1024 * 1024 && observed.sha256 === digest,
      CODE,
      'Installed runtime file changed since native verification: ' + path.basename(file),
    );
    fingerprints.set(normalized, digest);
  }
  assert(
    fingerprints.get(key(configurationPath)) === current.sha256 &&
      fingerprints.get(key(config.command)) === probe.command_sha256,
    CODE,
    'Probe did not fingerprint its configured launch',
  );
  const wrappers = config.args.filter((arg) => path.isAbsolute(arg) && /\.(?:py|mjs|js)$/i.test(arg));
  assert(
    wrappers.length > 0 &&
      wrappers.length <= 8 &&
      wrappers.every((file) => fingerprints.has(key(file))) &&
      fingerprints.get(key(wrappers[0]!)) === probe.wrapper_sha256,
    CODE,
    'Configured wrapper was not verified',
  );
  const idaDirectory = config.env?.IDADIR;
  assert(
    typeof idaDirectory === 'string' && path.isAbsolute(idaDirectory),
    CODE,
    'Native probe must identify the configured IDA installation',
  );
  for (const relative of ['idalib.dll', 'ida.dll', 'plugins/hexx64.dll'])
    assert(
      fingerprints.has(key(path.join(idaDirectory, relative))),
      CODE,
      'Native probe did not fingerprint ' + relative,
    );
  const paths = [...fingerprints.keys()];
  assert(
    paths.some((file) => file.includes('/site-packages/ida_pro_mcp/') && file.endsWith('.py')) &&
      paths.some((file) => file.includes('/site-packages/idapro/') && file.endsWith('.py')),
    CODE,
    'Native probe omitted installed IDA MCP or IDAlib package code',
  );
  return { manifest_sha256: manifestBytes.sha256, files_verified: fingerprints.size };
}
export async function verifyConfiguredIdaProbe(
  config: IdaConfiguration,
  configurationPath?: string,
): Promise<{
  probe: Record<string, any>;
  receipt_sha256: string;
  manifest_sha256: string;
  files_verified: number;
}> {
  assert(config.probe_receipt, 'IDA_PROBE_UNVERIFIED', 'A verified native probe is required');
  const receipt = await snapshot(config.probe_receipt, 1024 * 1024);
  const probe = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(receipt.bytes));
  assert(
    probe &&
      probe.status === 'completed' &&
      probe.revision === config.provider.revision &&
      probe.native_initialized === true &&
      probe.mcp_handshake === true &&
      probe.identity_verified === true &&
      probe.fixture?.disassembly === true &&
      probe.fixture?.decompilation === true &&
      typeof probe.checked_at === 'string' &&
      Number.isFinite(Date.parse(probe.checked_at)),
    'IDA_PROBE_UNVERIFIED',
    'Native fixture probe is missing required evidence',
  );
  const runtime = await verifyIdaRuntime(config, configurationPath, probe);
  return { probe, receipt_sha256: receipt.sha256, ...runtime };
}
export async function verifiedIdaSamples(value: unknown): Promise<IdaSample[]> {
  if (value === undefined) return [];
  assert(
    Array.isArray(value) && value.length <= 8,
    'IDA_PROBE_INVALID',
    'Native probe sample list is excessive',
  );
  const output: IdaSample[] = [];
  for (const item of value) {
    try {
      const sample = dataObject(
        item,
        ['id', 'label', 'file', 'sha256', 'description', 'address', 'scope_kind', 'provenance'],
        'IDA sample',
        'IDA_PROBE_INVALID',
      );
      assert(
        typeof sample.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(sample.id),
        'IDA_PROBE_INVALID',
        'IDA sample ID is invalid',
      );
      boundedText(sample.label, 256, 'Sample label');
      boundedText(sample.file, 4096, 'Sample file');
      boundedText(sample.description, 4096, 'Sample scope');
      assert(
        path.isAbsolute(sample.file) && typeof sample.sha256 === 'string' && DIGEST.test(sample.sha256),
        'IDA_PROBE_INVALID',
        'Sample file identity is invalid',
      );
      if (sample.address !== undefined)
        assert(
          typeof sample.address === 'string' && /^0x[0-9a-f]{1,16}$/.test(sample.address),
          'IDA_PROBE_INVALID',
          'Sample address is invalid',
        );
      const selected = await snapshot(sample.file, 128 * 1024 * 1024, true);
      if (selected.sha256 !== sample.sha256) continue;
      if (sample.scope_kind !== undefined)
        assert(
          sample.scope_kind === 'reference_fixture' || sample.scope_kind === 'derived_window',
          'IDA_PROBE_INVALID',
          'Unknown sample scope',
        );
      let provenance: IdaSample['provenance'];
      if (sample.provenance !== undefined) {
        const reference = dataObject(
          sample.provenance,
          ['file', 'sha256'],
          'Sample provenance',
          'IDA_PROBE_INVALID',
        );
        boundedText(reference.file, 4096, 'Provenance file');
        assert(
          path.isAbsolute(reference.file) &&
            typeof reference.sha256 === 'string' &&
            DIGEST.test(reference.sha256),
          'IDA_PROBE_INVALID',
          'Provenance reference is invalid',
        );
        const evidence = await snapshot(reference.file, 1024 * 1024, true);
        assert(
          evidence.sha256 === reference.sha256,
          'IDA_PROBE_INVALID',
          'Sample provenance identity changed',
        );
        JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(evidence.bytes));
        provenance = { file: reference.file, sha256: reference.sha256 };
      }
      assert(
        sample.scope_kind !== 'derived_window' || provenance,
        'IDA_PROBE_INVALID',
        'A derived sample requires verified provenance',
      );
      output.push({
        id: sample.id,
        label: sample.label,
        file: sample.file,
        sha256: sample.sha256,
        description: sample.description,
        ...(sample.address ? { address: sample.address as string } : {}),
        ...(sample.scope_kind ? { scope_kind: sample.scope_kind as IdaSample['scope_kind'] } : {}),
        ...(provenance ? { provenance } : {}),
      });
    } catch {
      /* Missing or changed examples are omitted; they cannot become unverified launch suggestions. */
    }
  }
  return output;
}
