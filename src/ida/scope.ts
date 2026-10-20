import path from 'node:path';
import { snapshot, type BinarySource } from '../binary-files.js';
import { rootDir } from '../shared.js';
import type { ArtifactRef } from '../types.js';
import type { WirefitService } from '../service.js';
import { idaCapabilities, loadIdaConfiguration } from './configuration.js';
import type { IdaSourceScope } from './types.js';

/** Resolve descriptive provenance only from the administrator's verified registry. */
export async function resolveIdaSourceScope(
  service: WirefitService,
  source: BinarySource,
  root = rootDir,
): Promise<{ scope: IdaSourceScope; artifacts: ArtifactRef[] }> {
  const unclassified: IdaSourceScope = {
    kind: 'unclassified',
    label: 'Unclassified input',
    description:
      'The analyzed input is identified by its recorded path and SHA-256. Original-target fidelity and whole-program completeness are not established.',
  };
  try {
    const config = await loadIdaConfiguration(root);
    if (!config?.probe_receipt) return { scope: unclassified, artifacts: [] };
    const receipt = await snapshot(config.probe_receipt, 1024 * 1024),
      probe = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(receipt.bytes));
    const same = (file: unknown) =>
      typeof file === 'string' &&
      (process.platform === 'win32'
        ? path.resolve(file).toLowerCase() === source.path.toLowerCase()
        : path.resolve(file) === source.path);
    // Avoid hashing the full runtime for unrelated manual inputs. Candidates still
    // require full capability verification before any annotation is trusted.
    if (
      !Array.isArray(probe.samples) ||
      probe.samples.length > 8 ||
      !probe.samples.some(
        (sample: Record<string, unknown>) => sample && same(sample.file) && sample.sha256 === source.sha256,
      )
    )
      return { scope: unclassified, artifacts: [] };
    const capability = await idaCapabilities(root);
    if (capability.status !== 'verified') return { scope: unclassified, artifacts: [] };
    const sample = capability.samples.find((item) => same(item.file) && item.sha256 === source.sha256);
    if (!sample?.scope_kind) return { scope: unclassified, artifacts: [] };
    const scope: IdaSourceScope = {
        kind: sample.scope_kind,
        label: sample.label,
        description: sample.description,
      },
      artifacts: ArtifactRef[] = [];
    if (sample.provenance) {
      const evidence = await snapshot(sample.provenance.file, 1024 * 1024, true);
      if (evidence.sha256 !== sample.provenance.sha256) return { scope: unclassified, artifacts: [] };
      scope.provenance_artifact = await service.store.putArtifact(evidence.bytes, 'application/json');
      artifacts.push(scope.provenance_artifact);
    }
    return { scope, artifacts };
  } catch {
    return { scope: unclassified, artifacts: [] };
  }
}
