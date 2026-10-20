import { describe, expect, it } from 'vitest';
import { createEvidence } from '../vendor/rea/src/domain/evidence.js';
import { createEvidenceBundle } from '../vendor/rea/src/domain/evidenceBundle.js';
import { createAnalysisProfile } from '../vendor/rea/src/domain/analysisProfile.js';
import { importPortableEvidence, interpretReaReply } from '../src/rea.js';

// Synthetic transport boundary fixtures built by the pinned upstream validator.
export function syntheticEvidence(result: any = { note: 'synthetic; not a Ghidra run' }) {
  const provider = { id: 'ghidra', name: 'Ghidra', version: '12.1.4' };
  return createEvidence({ path: '/synthetic/fixture', sha256: 'a'.repeat(64), format: 'elf', architecture: 'x86_64' }, provider, {
    operation: 'analyze_function', predicateType: 'rea.function-dossier', result, parameters: {},
    analysisProfile: createAnalysisProfile(provider, { mode: 'synthetic' }),
  });
}

describe('portable REA identity boundary (synthetic fixtures)', () => {
  it('authenticates actual canonical envelope and keeps declared unknowns', () => {
    const bundle = createEvidenceBundle([syntheticEvidence()]);
    const imported = importPortableEvidence(bundle);
    expect(imported.status).toBe('supported');
    expect(imported.records[0]?.normalized_result).toEqual({ note: 'synthetic; not a Ghidra run' });
    expect(imported.identity.parser_commit).toBe('27dc42d10249f0410904a75c0997842eb03b931c');
  });
  it('quarantines changed record semantic identity and changed profile identity', () => {
    const bundle = createEvidenceBundle([syntheticEvidence()]);
    const changedRecord = structuredClone(bundle);
    changedRecord.records[0]!.normalized_result = { note: 'tampered' };
    expect(importPortableEvidence(changedRecord)).toMatchObject({ status: 'attachment_only', records: [] });
    const changedProfile = structuredClone(bundle);
    changedProfile.records[0]!.analysis_profile!.parameters.mode = 'tampered';
    expect(importPortableEvidence(changedProfile).status).toBe('attachment_only');
  });
  it('quarantines noncanonical manifests, duplicate IDs and unsupported versions', () => {
    const bundle = createEvidenceBundle([syntheticEvidence()]);
    expect(importPortableEvidence({ ...bundle, providers: [] }).status).toBe('attachment_only');
    expect(importPortableEvidence({ ...bundle, records: [...bundle.records, ...bundle.records] }).status).toBe('attachment_only');
    expect(importPortableEvidence({ ...bundle, schema_version: 999 }).status).toBe('attachment_only');
  });
  it('retains success metadata and reads errors only from diagnostic text', () => {
    const metadata = { provenance: { untrusted_content: true, source: 'analysis_target' } };
    expect(interpretReaReply({ structuredContent: { value: 42 }, content: [], _meta: metadata })).toEqual({ ok: true, value: { value: 42 }, metadata, raw: { structuredContent: { value: 42 }, content: [], _meta: metadata } });
    expect(interpretReaReply({ isError: true, content: [{ type: 'text', text: '{"error":{"code":"not_found"}}' }], _meta: metadata })).toMatchObject({ ok: false, diagnostic: { error: { code: 'not_found' } }, metadata });
  });
});
