import { assert } from '../shared.js';
import { object } from './session.js';

function invalid(condition: unknown, message: string): asserts condition {
  assert(condition, 'IDA_REPLY_INVALID', message);
}
function address(value: unknown): value is string {
  return typeof value === 'string' && /^(?:0x)?[a-f0-9]{1,16}$/i.test(value);
}
export function canonicalIdaAddress(value: string): string {
  return '0x' + BigInt(value.toLowerCase().startsWith('0x') ? value : '0x' + value).toString(16);
}
function shortText(value: unknown, maximum = 4096): value is string {
  return typeof value === 'string' && value.length <= maximum;
}
function page(value: unknown): Record<string, unknown> {
  invalid(Array.isArray(value) && value.length === 1, 'IDA batch reply must contain one requested result');
  return object(value[0]);
}
function matchingAddress(actual: unknown, requested: unknown): void {
  invalid(
    address(actual) && address(requested) && canonicalIdaAddress(actual) === canonicalIdaAddress(requested),
    'IDA reply address does not match the requested address',
  );
}
function references(value: unknown, maximum: number): void {
  invalid(Array.isArray(value) && value.length <= maximum, 'IDA reference count exceeds the requested bound');
  for (const row of value) {
    const item = object(row);
    invalid(address(item.addr), 'IDA reference address is invalid');
    if (item.name !== undefined) invalid(shortText(item.name), 'IDA reference name is too large');
  }
}
/** Validate known result fields before promoting any provider data to normalized evidence. */
export function validateIdaToolData(tool: string, value: unknown, args: Record<string, unknown>): void {
  const item = object(value);
  switch (tool) {
    case 'server_health':
      invalid(item.status === 'ok' || item.healthy === true, 'IDA did not report a healthy database');
      return;
    case 'list_funcs':
    case 'entity_query':
    case 'type_query': {
      const result = page(value),
        maximum = Number(object(args.queries).count);
      invalid(
        Array.isArray(result.data) && result.data.length <= maximum,
        'IDA listing exceeds the requested page',
      );
      if (result.next_offset !== undefined && result.next_offset !== null)
        invalid(
          Number.isSafeInteger(result.next_offset) && Number(result.next_offset) >= 0,
          'IDA listing cursor is invalid',
        );
      for (const row of result.data) {
        const entry = object(row);
        if (tool === 'list_funcs')
          invalid(address(entry.addr) && shortText(entry.name), 'IDA function identity is invalid');
        if (tool === 'entity_query')
          invalid(
            address(entry.addr) && (shortText(entry.text, 65536) || shortText(entry.string, 65536)),
            'IDA string identity is invalid',
          );
        if (tool === 'type_query') invalid(shortText(entry.name), 'IDA type identity is invalid');
      }
      return;
    }
    case 'decompile':
      matchingAddress(item.addr, args.addr);
      invalid(
        address(item.addr) &&
          shortText(item.code, 262144) &&
          item.code.length > 0 &&
          item.code.split('\n').length <= 501,
        'IDA pseudocode is missing or exceeds its page bound',
      );
      return;
    case 'disasm': {
      matchingAddress(item.addr, args.addr);
      const listing = object(item.asm);
      invalid(
        address(item.addr) &&
          Array.isArray(listing.lines) &&
          listing.lines.length <= Number(args.max_instructions),
        'IDA assembly listing is missing or excessive',
      );
      for (const row of listing.lines) {
        const instruction = object(row);
        invalid(
          address(instruction.addr) && shortText(instruction.instruction, 8192),
          'IDA instruction is invalid',
        );
        if (instruction.comments !== undefined)
          invalid(
            Array.isArray(instruction.comments) &&
              instruction.comments.length <= 128 &&
              instruction.comments.every((comment) => shortText(comment)),
            'IDA instruction comments are excessive',
          );
      }
      return;
    }
    case 'basic_blocks': {
      const result = page(value);
      matchingAddress(result.addr, args.addrs);
      invalid(
        Array.isArray(result.blocks) && result.blocks.length <= Number(args.max_blocks),
        'IDA CFG is missing or excessive',
      );
      const seen = new Set<string>();
      let edges = 0;
      for (const row of result.blocks) {
        const block = object(row);
        invalid(address(block.start) && address(block.end), 'IDA basic block address is invalid');
        const start = canonicalIdaAddress(block.start);
        invalid(
          !seen.has(start) && BigInt(canonicalIdaAddress(block.end)) > BigInt(start),
          'IDA basic block identity or extent is invalid',
        );
        seen.add(start);
        invalid(
          Array.isArray(block.successors) &&
            block.successors.length <= 200 &&
            block.successors.every(address),
          'IDA basic block successors are invalid',
        );
        edges += block.successors.length;
        invalid(edges <= 4096, 'IDA CFG edge budget exceeded');
      }
      return;
    }
    case 'func_profile': {
      const result = page(value);
      if (result.target !== undefined) matchingAddress(result.target, object(args.queries).addr);
      invalid(Array.isArray(result.data) && result.data.length === 1, 'IDA function profile is missing');
      const profile = object(result.data[0]);
      if (profile.error) invalid(false, 'IDA function profile returned an error');
      if (profile.callers !== undefined) references(profile.callers, 200);
      if (profile.callees !== undefined) references(profile.callees, 200);
      return;
    }
    case 'xrefs_to': {
      const result = page(value);
      matchingAddress(result.addr, args.addrs);
      references(result.xrefs, Number(args.limit));
      for (const row of result.xrefs as unknown[]) {
        const ref = object(row);
        invalid(ref.type === 'code' || ref.type === 'data', 'IDA xref kind is invalid');
      }
      return;
    }
    case 'get_bytes': {
      const result = page(value),
        parts = typeof result.data === 'string' ? result.data.trim().split(/\s+/) : [];
      matchingAddress(result.addr, object(args.regions).addr);
      invalid(
        address(result.addr) &&
          parts.length === object(args.regions).size &&
          parts.every((part) => /^0x[0-9a-f]{1,2}$/i.test(part)),
        'IDA returned missing or malformed requested bytes',
      );
      return;
    }
  }
}
export function normalizeIdaCfg(rows: unknown[]): {
  nodes: Record<string, unknown>[];
  edges: { source: string; target: string }[];
} {
  const nodes = rows.map((row) => {
    const block = object(row),
      start = canonicalIdaAddress(block.start as string);
    return {
      ...block,
      id: start,
      start,
      end: canonicalIdaAddress(block.end as string),
      successors: (block.successors as string[]).map(canonicalIdaAddress),
    };
  });
  const edges = nodes.flatMap((node) =>
    (node.successors as string[]).map((target) => ({ source: node.start, target })),
  );
  return { nodes, edges };
}
