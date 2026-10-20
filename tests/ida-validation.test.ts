import { describe, it, expect } from 'vitest';
import { validateIdaAnalysisRequest } from '../src/ida/index.js';

describe('IDA request boundary', () => {
  it('accepts the finite read-only query set and canonicalizes addresses', () => {
    const request = validateIdaAnalysisRequest({
      file: 'sample.exe',
      queries: [
        { kind: 'overview' },
        { kind: 'functions', pattern: 'main', offset: 0, limit: 20 },
        { kind: 'strings' },
        { kind: 'function', address: '0xABC' },
        { kind: 'xrefs', address: '0x0' },
        { kind: 'bytes', address: '0xffffffffffffffff', size: 4096 },
        { kind: 'types', limit: 200 },
      ],
      timeout_ms: 600000,
    });
    expect(request.queries[3]).toEqual({ kind: 'function', address: '0xabc' });
    expect(request.queries[5]).toEqual({ kind: 'bytes', address: '0xffffffffffffffff', size: 4096 });
  });
  it.each([
    { file: 'x', queries: [] },
    { file: 'x', queries: Array.from({ length: 17 }, () => ({ kind: 'overview' })) },
    { file: 'x', queries: [{ kind: 'py_eval', code: 'print(1)' }] },
    { file: 'x', queries: [{ kind: 'overview', tool: 'py_eval' }] },
    { file: 'x', queries: [{ kind: 'function', address: '0x10000000000000000' }] },
    { file: 'x', queries: [{ kind: 'function', address: 'main' }] },
    { file: 'x', queries: [{ kind: 'bytes', address: '0x0', size: 4097 }] },
    { file: 'x', queries: [{ kind: 'functions', limit: 0 }] },
    { file: 'x', queries: [{ kind: 'strings', offset: 1000001 }] },
    { file: 'x', queries: [{ kind: 'types', pattern: 'x'.repeat(257) }] },
    { file: 'x', queries: [{ kind: 'overview' }], timeout_ms: 0 },
    { file: 'x', queries: [{ kind: 'overview' }], command: 'python' },
    { file: 'x\0', queries: [{ kind: 'overview' }] },
    { file: 'x', queries: [{ kind: 'bytes', address: '0x0', size: NaN }] },
  ])('rejects unsupported or unbounded input %#', (input) => {
    expect(() => validateIdaAnalysisRequest(input)).toThrow();
  });
  it('does not retain caller-owned query objects', () => {
    const input = { file: 'x', queries: [{ kind: 'overview' }] };
    const selected = validateIdaAnalysisRequest(input);
    input.queries[0]!.kind = 'py_eval';
    expect(selected.queries).toEqual([{ kind: 'overview' }]);
  });
  it('rejects accessors rather than executing untrusted request code', () => {
    let evaluated = false;
    const input = {
      get file() {
        evaluated = true;
        return 'x';
      },
      queries: [{ kind: 'overview' }],
    };
    expect(() => validateIdaAnalysisRequest(input)).toThrow();
    expect(evaluated).toBe(false);
  });
});
