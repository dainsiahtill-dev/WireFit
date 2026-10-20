import { assert } from '../shared.js';
import type { IdaAnalysisRequest, IdaQuery } from './types.js';

const CODE = 'IDA_REQUEST_INVALID';
export function dataObject(
  value: unknown,
  allowed: readonly string[],
  label: string,
  code = CODE,
): Record<string, unknown> {
  assert(
    value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null),
    code,
    label + ' must be a plain object',
  );
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    assert(
      typeof key === 'string' && allowed.includes(key) && descriptor?.enumerable && 'value' in descriptor,
      code,
      label + ' has unsupported or non-data fields',
    );
  }
  return value as Record<string, unknown>;
}
export function boundedText(
  value: unknown,
  maximum: number,
  label: string,
  empty = false,
  code = CODE,
): asserts value is string {
  assert(
    typeof value === 'string' &&
      (empty || value.length > 0) &&
      value.length <= maximum &&
      !value.includes('\0'),
    code,
    label + ' must be a bounded string without NUL',
  );
}
function integer(value: unknown, minimum: number, maximum: number, label: string): void {
  assert(
    typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum,
    CODE,
    label + ' is outside its allowed range',
  );
}
function query(value: unknown): IdaQuery {
  const base = dataObject(value, ['kind', 'pattern', 'offset', 'limit', 'address', 'size'], 'IDA query');
  const kind = base.kind;
  assert(
    typeof kind === 'string' &&
      ['overview', 'functions', 'strings', 'function', 'xrefs', 'bytes', 'types'].includes(kind),
    CODE,
    'Unsupported IDA query kind',
  );
  if (kind === 'overview') {
    dataObject(value, ['kind'], 'Overview query');
    return { kind };
  }
  if (kind === 'functions' || kind === 'strings' || kind === 'types') {
    dataObject(value, ['kind', 'pattern', 'offset', 'limit'], 'Paged query');
    if (base.pattern !== undefined) boundedText(base.pattern, 256, 'Pattern', true);
    if (base.offset !== undefined) integer(base.offset, 0, 1_000_000, 'Offset');
    if (base.limit !== undefined) integer(base.limit, 1, 200, 'Limit');
    return {
      kind,
      ...(base.pattern === undefined ? {} : { pattern: base.pattern as string }),
      ...(base.offset === undefined ? {} : { offset: base.offset as number }),
      ...(base.limit === undefined ? {} : { limit: base.limit as number }),
    };
  }
  dataObject(value, kind === 'bytes' ? ['kind', 'address', 'size'] : ['kind', 'address'], 'Address query');
  assert(
    typeof base.address === 'string' && /^0x[0-9a-fA-F]{1,16}$/.test(base.address),
    CODE,
    'Address must be 0x hexadecimal within 64 bits',
  );
  const address = '0x' + BigInt(base.address).toString(16);
  if (kind === 'bytes') {
    integer(base.size, 1, 4096, 'Byte size');
    return { kind, address, size: base.size as number };
  }
  return { kind: kind as 'function' | 'xrefs', address };
}
export function validateIdaAnalysisRequest(value: unknown): IdaAnalysisRequest {
  const input = dataObject(value, ['file', 'queries', 'timeout_ms'], 'IDA request');
  boundedText(input.file, 4096, 'Input file');
  assert(
    Array.isArray(input.queries) && input.queries.length >= 1 && input.queries.length <= 16,
    CODE,
    'Provide 1..16 IDA queries',
  );
  const queries: IdaQuery[] = [];
  for (let index = 0; index < input.queries.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input.queries, String(index));
    assert(descriptor && 'value' in descriptor, CODE, 'Queries must be a dense data array');
    queries.push(query(descriptor.value));
  }
  assert(
    Reflect.ownKeys(input.queries).length === input.queries.length + 1,
    CODE,
    'Queries cannot contain additional fields',
  );
  if (input.timeout_ms !== undefined) integer(input.timeout_ms, 1, 600000, 'timeout_ms');
  return {
    file: input.file,
    queries,
    ...(input.timeout_ms === undefined ? {} : { timeout_ms: input.timeout_ms as number }),
  };
}
