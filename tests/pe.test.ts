import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { inspectPe, PeFormatError } from '../src/pe.js';

// Hand-built PE layouts exercise structural boundaries without executing code.
function fixture(is64 = false): Uint8Array {
  const bytes = new Uint8Array(0x800);
  const view = new DataView(bytes.buffer);
  const optional = 0x98;
  const optionalSize = is64 ? 0xf0 : 0xe0;
  const sectionTable = optional + optionalSize;
  const text = new TextEncoder();
  const ascii = (offset: number, value: string) => bytes.set(text.encode(value), offset);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 0x80, true);
  view.setUint32(0x80, 0x4550, true);
  view.setUint16(0x84, is64 ? 0x8664 : 0x14c, true);
  view.setUint16(0x86, 2, true);
  view.setUint16(0x94, optionalSize, true);
  view.setUint16(optional, is64 ? 0x20b : 0x10b, true);
  view.setUint32(optional + 16, 0x1010, true);
  if (is64) view.setBigUint64(optional + 24, 0x20000000000001n, true);
  else view.setUint32(optional + 28, 0x400000, true);
  view.setUint32(optional + 32, 0x1000, true);
  view.setUint32(optional + 36, 0x200, true);
  view.setUint32(optional + 56, 0x3000, true);
  view.setUint32(optional + 60, 0x200, true);
  view.setUint32(optional + (is64 ? 108 : 92), 16, true);
  const imports = optional + (is64 ? 112 : 96) + 8;
  view.setUint32(imports, 0x2000, true);
  view.setUint32(imports + 4, 40, true);
  ascii(sectionTable, '.text');
  view.setUint32(sectionTable + 8, 0x300, true);
  view.setUint32(sectionTable + 12, 0x1000, true);
  view.setUint32(sectionTable + 16, 0x200, true);
  view.setUint32(sectionTable + 20, 0x200, true);
  view.setUint32(sectionTable + 36, 0x60000020, true);
  ascii(sectionTable + 40, '.idata');
  view.setUint32(sectionTable + 48, 0x200, true);
  view.setUint32(sectionTable + 52, 0x2000, true);
  view.setUint32(sectionTable + 56, 0x200, true);
  view.setUint32(sectionTable + 60, 0x400, true);
  view.setUint32(sectionTable + 76, 0xc0000040, true);
  bytes.set([0x55, 0x8b, 0xec, 0xc3], 0x210);
  view.setUint32(0x400, 0x2040, true);
  view.setUint32(0x40c, 0x2080, true);
  view.setUint32(0x410, 0x2060, true);
  if (is64) {
    view.setBigUint64(0x440, 0x2090n, true);
    view.setBigUint64(0x448, 0x8000000000000007n, true);
  } else {
    view.setUint32(0x440, 0x2090, true);
    view.setUint32(0x444, 0x80000007, true);
  }
  ascii(0x480, 'KERNEL32.dll');
  view.setUint16(0x490, 17, true);
  ascii(0x492, 'ExitProcess');
  return bytes;
}

function edit(bytes: Uint8Array, offset: number, value: number, width: 2 | 4 = 4): Uint8Array {
  const copy = new Uint8Array(bytes);
  const view = new DataView(copy.buffer);
  if (width === 2) view.setUint16(offset, value, true);
  else view.setUint32(offset, value, true);
  return copy;
}

function diagnostic(bytes: Uint8Array, code: string) {
  const result = inspectPe(bytes);
  expect(result.imports).toEqual([]);
  expect(result.imports_complete).toBe(false);
  expect(result.diagnostics.some(item => item.code === code)).toBe(true);
  return result;
}

describe('bounded PE inspection', () => {
  it('reads PE32 identity, exact entry bytes, section metadata and imports', () => {
    const bytes = fixture();
    const result = inspectPe(bytes);
    expect(result.schema_version).toBe(1);
    expect(result.sha256).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(result.size_bytes).toBe(2048);
    expect(result.format).toBe('PE32');
    expect(result.architecture).toBe('x86');
    expect(result.image_base).toBe('0x400000');
    expect(result.entry_point).toEqual({rva:4112,va:'0x401010',file_offset:528,section:'.text',bytes_hex:'558becc3000000000000000000000000'});
    expect(result.sections[0]).toMatchObject({name:'.text',rva:4096,virtual_size:768,raw_offset:512,raw_size:512,characteristics:0x60000020});
    expect(result.sections[0]!.entropy).toBeGreaterThan(0);
    expect(result.sections[0]!.entropy).toBeLessThan(0.1);
    expect(result.imports).toEqual([{library:'KERNEL32.dll',symbols:[{name:'ExitProcess',hint:17},{ordinal:7}]}]);
    expect(result.imports_complete).toBe(true);
    expect(result.indicators.packed_suspected).toBe(false);
    expect(result.diagnostics).toEqual([]);
  });

  it('keeps PE32+ high image bases and VAs exact and reads 64-bit ordinals', () => {
    const result = inspectPe(fixture(true));
    expect(result.format).toBe('PE32+');
    expect(result.architecture).toBe('x86_64');
    expect(result.image_base).toBe('0x20000000000001');
    expect(result.entry_point.va).toBe('0x20000000001011');
    expect(result.imports[0]!.symbols).toEqual([{name:'ExitProcess',hint:17},{ordinal:7}]);
  });


  it('rejects an image whose virtual address range overflows its address width', () => {
    const pe32 = edit(fixture(), 0xb4, 0xfffff000);
    expect(() => inspectPe(pe32)).toThrow(PeFormatError);
    const pe64 = fixture(true);
    new DataView(pe64.buffer).setBigUint64(0xb0, 0xfffffffffffff000n, true);
    expect(() => inspectPe(pe64)).toThrow(PeFormatError);
  });
  it('accepts a byte view without reading its underlying prefix or suffix', () => {
    const storage = new Uint8Array(0x900);
    storage.set(fixture(), 0x80);
    expect(inspectPe(storage.subarray(0x80, 0x880)).size_bytes).toBe(2048);
    expect(inspectPe(storage.subarray(0x80, 0x880)).entry_point.file_offset).toBe(528);
  });

  it.each([
    ['empty input', new Uint8Array()],
    ['bad DOS signature', edit(fixture(), 0, 0, 2)],
    ['overflowed PE offset', edit(fixture(), 0x3c, 0xfffffff0)],
    ['bad PE signature', edit(fixture(), 0x80, 0)],
    ['unsupported optional magic', edit(fixture(), 0x98, 0x107, 2)],
    ['short optional header', edit(fixture(), 0x94, 40, 2)],
    ['oversized section count', edit(fixture(), 0x86, 0xffff, 2)],
    ['truncated section headers', fixture().subarray(0, 0x190)],
  ])('rejects %s with a typed format error', (_name, bytes) => {
    expect(() => inspectPe(bytes)).toThrow(PeFormatError);
  });

  it('does not map an entry point in a section virtual-only tail to file data', () => {
    const result = inspectPe(edit(fixture(), 0xa8, 0x1250));
    expect(result.entry_point).toEqual({rva:4688,va:'0x401250',file_offset:null,section:'.text',bytes_hex:''});
    expect(result.diagnostics.some(item => item.code === 'ENTRY_POINT_NOT_FILE_BACKED')).toBe(true);
  });

  it('bounds entry bytes at the containing raw section instead of bleeding into another section', () => {
    const result = inspectPe(edit(fixture(), 0xa8, 0x11fe));
    expect(result.entry_point.file_offset).toBe(0x3fe);
    expect(result.entry_point.bytes_hex).toBe('0000');
  });


  it('does not let empty virtual sections truncate another section mapped bytes', () => {
    let bytes = edit(edit(fixture(), 0x100, 0), 0x104, 0);
    bytes = edit(edit(edit(bytes, 0x1ac, 0x1018), 0x1a8, 0), 0x1b0, 0);
    expect(inspectPe(bytes).entry_point.bytes_hex).toBe('558becc3000000000000000000000000');
  });
  it('records truncated raw sections without manufacturing unavailable bytes', () => {
    const bytes = edit(fixture(), 0x178 + 20, 0x7f0);
    const result = inspectPe(bytes);
    expect(result.entry_point.file_offset).toBe(null);
    expect(result.sections[0]!.raw_size).toBe(512);
    expect(result.diagnostics.some(item => item.code === 'SECTION_RAW_TRUNCATED')).toBe(true);
  });

  it('rejects a fake mapped RVA outside SizeOfImage', () => {
    const bytes = edit(edit(fixture(), 0x178 + 12, 0xfffff000), 0xa8, 0xfffff010);
    const result = inspectPe(bytes);
    expect(result.entry_point.file_offset).toBe(null);
    expect(result.diagnostics.some(item => item.code === 'SECTION_VIRTUAL_RANGE_INVALID')).toBe(true);
  });

  it('discards all import results if a later descriptor is malformed', () => {
    const bytes = fixture();
    const view = new DataView(bytes.buffer);
    view.setUint32(0x414, 0x2040, true);
    view.setUint32(0x420, 0x2500, true);
    diagnostic(bytes, 'IMPORT_DIRECTORY_INVALID');
  });

  it('does not map an import library string in a virtual-only tail', () => {
    diagnostic(edit(fixture(), 0x40c, 0x2250), 'IMPORT_DIRECTORY_INVALID');
  });

  it('rejects missing import descriptor terminators within the declared table size', () => {
    diagnostic(edit(fixture(), 0x104, 20), 'IMPORT_DIRECTORY_INVALID');
  });

  it('rejects unterminated import strings without scanning into a neighboring region', () => {
    const bytes = edit(fixture(), 0x40c, 0x21f0);
    bytes.fill(65, 0x5f0, 0x600);
    diagnostic(bytes, 'IMPORT_DIRECTORY_INVALID');
  });

  it('rejects invalid 64-bit name thunks and reserved ordinal bits', () => {
    const bytes = fixture(true);
    new DataView(bytes.buffer).setBigUint64(0x440, 0x100002090n, true);
    diagnostic(bytes, 'IMPORT_DIRECTORY_INVALID');
    const ordinal = fixture();
    new DataView(ordinal.buffer).setUint32(0x444, 0x80010007, true);
    diagnostic(ordinal, 'IMPORT_DIRECTORY_INVALID');
  });



  it('retains one immutable inspection identity when the caller later overwrites its bytes', () => {
    const bytes = fixture();
    const originalHash = createHash('sha256').update(bytes).digest('hex');
    const result = inspectPe(bytes);
    bytes.fill(0);
    expect(result.sha256).toBe(originalHash);
    expect(result.entry_point.bytes_hex).toBe('558becc3000000000000000000000000');
    expect(result.imports[0]!.library).toBe('KERNEL32.dll');
  });

  it('uses the IAT as the lookup table when OriginalFirstThunk is absent', () => {
    const bytes = fixture();
    bytes.copyWithin(0x460, 0x440, 0x44c);
    new DataView(bytes.buffer).setUint32(0x400, 0, true);
    expect(inspectPe(bytes).imports).toEqual([{library:'KERNEL32.dll',symbols:[{name:'ExitProcess',hint:17},{ordinal:7}]}]);
  });

  it('bounds an overflowing directory count to the declared optional header', () => {
    const result = inspectPe(edit(fixture(), 0xf4, 0xffffffff));
    expect(result.imports).toEqual([]);
    expect(result.imports_complete).toBe(false);
    expect(result.diagnostics.some(item => item.code === 'DIRECTORY_COUNT_INVALID')).toBe(true);
  });

  it('treats a zero entry RVA as absent even when headers are file-backed', () => {
    const result = inspectPe(edit(fixture(), 0xa8, 0));
    expect(result.entry_point).toEqual({rva:0,va:'0x400000',file_offset:null,section:null,bytes_hex:''});
    expect(result.diagnostics.some(item => item.code === 'ENTRY_POINT_NOT_FILE_BACKED')).toBe(false);
  });

  it('bounds descriptor walks even when a later terminator is valid and file-backed', () => {
    const bytes = new Uint8Array(0x20400);
    bytes.set(fixture());
    const view = new DataView(bytes.buffer);
    view.setUint32(0xd0, 0x23000, true);
    view.setUint32(0x1a8, 0x20000, true);
    view.setUint32(0x1b0, 0x20000, true);
    view.setUint32(0x104, 4097 * 20, true);
    bytes.fill(0, 0x400);
    for (let index = 0; index < 4096; index++) {
      view.setUint32(0x400 + index * 20, 0x1dc00, true);
      view.setUint32(0x40c + index * 20, 0x1dc20, true);
      view.setUint32(0x410 + index * 20, 0x1dc00, true);
    }
    bytes.set(new TextEncoder().encode('KERNEL32.dll'), 0x1c020);
    diagnostic(bytes, 'IMPORT_DIRECTORY_INVALID');
  });
  it('rejects the reserved PE32+ name-thunk bit even when its high RVA maps to raw data', () => {
    const bytes = fixture(true);
    const view = new DataView(bytes.buffer);
    view.setUint32(0xd0, 0x80003000, true);
    view.setUint32(0x1bc, 0x80002000, true);
    view.setUint32(0x110, 0x80002000, true);
    view.setUint32(0x400, 0x80002040, true);
    view.setUint32(0x40c, 0x80002080, true);
    view.setUint32(0x410, 0x80002060, true);
    view.setBigUint64(0x440, 0x80002090n, true);
    diagnostic(bytes, 'IMPORT_DIRECTORY_INVALID');
  });

  it('does not read a header entry point through an overlapping section boundary', () => {
    const bytes = edit(edit(fixture(), 0xa8, 0x160), 0x178 + 40 + 12, 0x168);
    const result = inspectPe(bytes);
    expect(result.entry_point.file_offset).toBe(0x160);
    expect(result.entry_point.bytes_hex).toHaveLength(16);
    expect(result.diagnostics.some(item => item.code === 'SECTION_VIRTUAL_OVERLAP')).toBe(true);
  });
  it('handles no import directory without inventing missing import failures', () => {
    const bytes = edit(edit(fixture(), 0x100, 0), 0x104, 0);
    const result = inspectPe(bytes);
    expect(result.imports).toEqual([]);
    expect(result.imports_complete).toBe(true);
  });

  it('reports ambiguous section mappings instead of choosing attacker-controlled first match', () => {
    const bytes = edit(fixture(), 0x178 + 40 + 12, 0x1000);
    const result = inspectPe(bytes);
    expect(result.entry_point.file_offset).toBe(null);
    expect(result.diagnostics.some(item => item.code === 'SECTION_VIRTUAL_OVERLAP')).toBe(true);
  });

  it('uses multiple conservative packing signals without asserting a packer family', () => {
    const bytes = fixture();
    for (let index = 0x200; index < 0x400; index++) bytes[index] = index & 0xff;
    const result = inspectPe(edit(bytes, 0x178 + 36, 0xe0000020));
    expect(result.sections[0]!.entropy).toBe(8);
    expect(result.indicators.packed_suspected).toBe(true);
    expect(result.indicators.reasons.join(' ')).toMatch(/entropy/i);
    expect(result.indicators.reasons.join(' ')).toMatch(/writable.*executable/i);
    expect(result.indicators.reasons.join(' ')).not.toMatch(/VMProtect|Themida|WinLicense/i);
    const entropyAlone = inspectPe(bytes);
    expect(entropyAlone.indicators.packed_suspected).toBe(false);
  });

  it.skipIf(!existsSync(path.resolve('artifacts/native/fixture-build/wirefit-fixture.exe')))('inspects a real locally compiled source-known PE without executing it', () => {
    const bytes = readFileSync(path.resolve('artifacts/native/fixture-build/wirefit-fixture.exe'));
    const result = inspectPe(bytes);
    expect(result.format).toBe('PE32+');
    expect(result.architecture).toBe('x86_64');
    expect(result.entry_point.file_offset).not.toBe(null);
    expect(result.imports.some(item => item.library.toLowerCase() === 'kernel32.dll')).toBe(true);
    expect(result.imports_complete).toBe(true);
  });

  const corpus = '.upstream/vmp-windows/2fb7ad84a90a73c950c39eccbad81cc2f6c25c33/VMProtect 3';
  it.skipIf(!existsSync(path.join(corpus, 'adder.vmp.exe')))('inspects three pinned protected PE fixtures without asserting recovery or family detection', () => {
    for (const name of ['adder.vmp.exe', 'bitwise.vmp.exe', 'multiadder.vmp.exe']) {
      const result = inspectPe(readFileSync(path.join(corpus, name)));
      expect(result.format).toBe('PE32+');
      expect(result.architecture).toBe('x86_64');
      expect(result.entry_point.file_offset).not.toBe(null);
      expect(result.imports).toHaveLength(7);
      expect(result.imports_complete).toBe(true);
      expect(result.diagnostics).toEqual([]);
    }
  });
});




function tlsFixture(is64 = false): Uint8Array {
  const bytes = fixture(is64);
  const view = new DataView(bytes.buffer);
  const base = is64 ? 0x20000000000001n : 0x400000n;
  const directory = 0x98 + (is64 ? 112 : 96) + 9 * 8;
  view.setUint32(directory, 0x2100, true);
  view.setUint32(directory + 4, is64 ? 40 : 24, true);
  const width = is64 ? 8 : 4;
  const pointer = (offset: number, value: bigint) => {
    if (is64) view.setBigUint64(offset, value, true);
    else view.setUint32(offset, Number(value), true);
  };
  pointer(0x500, base + 0x2180n);
  pointer(0x500 + width, base + 0x2188n);
  pointer(0x500 + width * 2, base + 0x2130n);
  pointer(0x500 + width * 3, base + 0x2140n);
  view.setUint32(0x500 + width * 4, 8, true);
  view.setUint32(0x504 + width * 4, 0x300000, true);
  pointer(0x540, base + 0x1010n);
  pointer(0x540 + width, base + 0x1020n);
  return bytes;
}

const sehProlog = Uint8Array.from([
  0x68, 0x08, 0x13, 0x4b, 0x00, 0x64, 0xa1, 0, 0, 0, 0, 0x50,
  0x8b, 0x44, 0x24, 0x10, 0x89, 0x6c, 0x24, 0x10, 0x8d, 0x6c, 0x24, 0x10,
  0x2b, 0xe0, 0x53,
]);

describe('entry assessment and bounded TLS metadata', () => {
  it('labels the observed x86 SEH prolog as a heuristic without changing the declared entry', () => {
    const bytes = fixture();
    bytes.set(sehProlog, 0x210);
    const result = inspectPe(bytes);
    expect(result.entry_point.rva).toBe(0x1010);
    expect(result.entry_assessment).toEqual({kind:'x86_seh_prolog_helper_like',basis:'heuristic',inspected_bytes:64});
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'ENTRY_POINT_SEH_PROLOG_HEURISTIC',message:expect.stringMatching(/does not identify.*original entry/i)}));
  });

  it('does not classify benign or non-x86 entry bytes as an SEH helper', () => {
    expect(inspectPe(fixture()).entry_assessment).toEqual({kind:'unclassified',basis:'none',inspected_bytes:64});
    const bytes = fixture(true);
    bytes.set(sehProlog, 0x210);
    expect(inspectPe(bytes).entry_assessment.kind).toBe('unclassified');
    expect(inspectPe(bytes).diagnostics).toEqual([]);
  });

  it('requires the full helper pattern within a single file-backed mapping', () => {
    const bytes = edit(fixture(), 0xa8, 0x11f0);
    bytes.set(sehProlog, 0x3f0);
    const result = inspectPe(bytes);
    expect(result.entry_assessment).toEqual({kind:'unclassified',basis:'none',inspected_bytes:16});
    expect(result.diagnostics.some(item => item.code === 'ENTRY_POINT_SEH_PROLOG_HEURISTIC')).toBe(false);
  });

  it('distinguishes absent and non-file-backed entry assessments', () => {
    expect(inspectPe(edit(fixture(), 0xa8, 0)).entry_assessment).toEqual({kind:'absent',basis:'none',inspected_bytes:0});
    expect(inspectPe(edit(fixture(), 0xa8, 0x1250)).entry_assessment).toEqual({kind:'unmapped',basis:'none',inspected_bytes:0});
  });

  it('treats missing TLS as a complete empty result', () => {
    const result = inspectPe(fixture());
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(true);
  });

  it('reads PE32 TLS directory fields and file-backed callback metadata', () => {
    const result = inspectPe(tlsFixture());
    expect(result.tls_complete).toBe(true);
    expect(result.tls).toEqual({
      directory_rva:0x2100,directory_size:24,
      start_address_of_raw_data:'0x402180',end_address_of_raw_data:'0x402188',
      address_of_index:'0x402130',address_of_callbacks:'0x402140',
      size_of_zero_fill:8,characteristics:0x300000,
      callbacks:[
        {va:'0x401010',rva:0x1010,file_offset:0x210},
        {va:'0x401020',rva:0x1020,file_offset:0x220},
      ],
    });
    expect(result.imports_complete).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });

  it('preserves exact PE32+ TLS addresses above the safe integer range', () => {
    const result = inspectPe(tlsFixture(true));
    expect(result.tls_complete).toBe(true);
    expect(result.tls).toMatchObject({
      directory_size:40,start_address_of_raw_data:'0x20000000002181',
      end_address_of_raw_data:'0x20000000002189',address_of_index:'0x20000000002131',
      address_of_callbacks:'0x20000000002141',
      callbacks:[
        {va:'0x20000000001011',rva:0x1010,file_offset:0x210},
        {va:'0x20000000001021',rva:0x1020,file_offset:0x220},
      ],
    });
  });

  it('allows an absent raw template and callback array', () => {
    const bytes = tlsFixture();
    bytes.fill(0, 0x500, 0x508);
    new DataView(bytes.buffer).setUint32(0x50c, 0, true);
    const result = inspectPe(bytes);
    expect(result.tls_complete).toBe(true);
    expect(result.tls).toMatchObject({start_address_of_raw_data:'0x0',end_address_of_raw_data:'0x0',address_of_callbacks:'0x0',callbacks:[]});
  });

  it.each([
    ['PE32 directory below its fixed size', false, 0x98 + 96 + 9 * 8 + 4, 23],
    ['PE32+ directory below its fixed size', true, 0x98 + 112 + 9 * 8 + 4, 39],
    ['directory in a virtual-only tail', false, 0x98 + 96 + 9 * 8, 0x2250],
    ['directory crossing the raw section boundary', false, 0x98 + 96 + 9 * 8, 0x21f0],
    ['declared directory outside the image', false, 0x98 + 96 + 9 * 8 + 4, 0x1000],
    ['zero directory RVA with nonzero size', false, 0x98 + 96 + 9 * 8, 0],
    ['callback array below the image base', false, 0x50c, 0x3fffff],
    ['callback array beyond the image', false, 0x50c, 0x403000],
    ['callback array in a virtual-only tail', false, 0x50c, 0x402250],
    ['callback in a virtual-only tail after a valid callback', false, 0x544, 0x401250],
    ['callback outside the image', false, 0x540, 0x403000],
    ['index field crossing its virtual section boundary', false, 0x508, 0x4021fe],
    ['raw template ending before its start', false, 0x504, 0x40217f],
    ['raw template ending beyond available section bytes', false, 0x504, 0x402201],
    ['raw template with only one nonzero endpoint', false, 0x500, 0],
  ] as const)('reports %s as transactionally incomplete TLS', (_label, is64, offset, value) => {
    const result = inspectPe(edit(tlsFixture(is64), offset, value));
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'TLS_DIRECTORY_INVALID'}));
    expect(result.imports_complete).toBe(true);
    expect(result.imports[0]!.library).toBe('KERNEL32.dll');
  });

  it('rejects a PE32+ callback VA with high bits that would truncate to a valid RVA', () => {
    const bytes = tlsFixture(true);
    new DataView(bytes.buffer).setBigUint64(0x540, 0x1020000000001011n, true);
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'TLS_DIRECTORY_INVALID'}));
  });

  it('does not use an array terminator beyond available raw bytes', () => {
    const bytes = edit(tlsFixture(), 0x50c, 0x4021fc);
    new DataView(bytes.buffer).setUint32(0x5fc, 0x401010, true);
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
  });

  it.each([false, true])('permits 64 TLS callbacks with a terminator but rejects a 65th (PE32+ = %s)', is64 => {
    const bytes = new Uint8Array(0x900);
    bytes.set(tlsFixture(is64));
    const view = new DataView(bytes.buffer);
    const sectionTable = 0x98 + (is64 ? 0xf0 : 0xe0);
    view.setUint32(sectionTable + 48, 0x500, true);
    view.setUint32(sectionTable + 56, 0x500, true);
    const width = is64 ? 8 : 4;
    const callback = is64 ? 0x20000000001011n : 0x401010n;
    bytes.fill(0, 0x540);
    for (let index = 0; index < 64; index++) {
      if (is64) view.setBigUint64(0x540 + index * width, callback, true);
      else view.setUint32(0x540 + index * width, Number(callback), true);
    }
    expect(inspectPe(bytes).tls_complete).toBe(true);
    expect(inspectPe(bytes).tls!.callbacks).toHaveLength(64);
    if (is64) view.setBigUint64(0x540 + 64 * width, callback, true);
    else view.setUint32(0x540 + 64 * width, Number(callback), true);
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'TLS_DIRECTORY_INVALID',message:expect.stringMatching(/limit/i)}));
  });

  it('marks TLS unknown when the data-directory count cannot be trusted', () => {
    const result = inspectPe(edit(tlsFixture(), 0xf4, 0xffffffff));
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'DIRECTORY_COUNT_INVALID'}));
  });

  it('retains an invalid exact TLS VA in diagnostics without publishing a valid callback prefix', () => {
    const bytes = tlsFixture(true);
    new DataView(bytes.buffer).setBigUint64(0x548, 0x1020000000001011n, true);
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({
      code:'TLS_DIRECTORY_INVALID',message:expect.stringContaining('0x1020000000001011'),
    }));
  });
});

function setTlsPointer(bytes: Uint8Array, is64: boolean, field: 0 | 1 | 2 | 3, value: bigint): void {
  const view = new DataView(bytes.buffer);
  if (is64) view.setBigUint64(0x500 + field * 8, value, true);
  else view.setUint32(0x500 + field * 4, Number(value), true);
}

function tlsWithBssFixture(is64: boolean): Uint8Array {
  const bytes = tlsFixture(is64);
  const view = new DataView(bytes.buffer);
  const bss = 0x98 + (is64 ? 0xf0 : 0xe0) + 80;
  view.setUint16(0x86, 3, true);
  bytes.set(new TextEncoder().encode('.bss'), bss);
  view.setUint32(bss + 8, 0x800, true);
  view.setUint32(bss + 12, 0x2800, true);
  view.setUint32(bss + 36, 0xc0000080, true);
  return bytes;
}

describe.each([false, true])('TLS initialized data and loader-written storage (PE32+ = %s)', is64 => {
  const base = is64 ? 0x20000000000001n : 0x400000n;

  it.each([
    ['image start', 0],
    ['virtual-only section tail', 0x1250],
    ['section end', 0x2200],
    ['image end', 0x3000],
  ] as const)('accepts an empty nonzero raw template at %s without requiring file bytes', (_label, rva) => {
    const bytes = tlsFixture(is64);
    setTlsPointer(bytes, is64, 0, base + BigInt(rva));
    setTlsPointer(bytes, is64, 1, base + BigInt(rva));
    const result = inspectPe(bytes);
    expect(result.tls_complete).toBe(true);
    expect(result.tls?.callbacks).toHaveLength(2);
    expect(result.diagnostics).toEqual([]);
  });

  it.each([
    ['below image base', -1],
    ['beyond image end', 0x3001],
  ] as const)('rejects empty raw-template addresses %s', (_label, rva) => {
    const bytes = tlsFixture(is64);
    setTlsPointer(bytes, is64, 0, base + BigInt(rva));
    setTlsPointer(bytes, is64, 1, base + BigInt(rva));
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'TLS_DIRECTORY_INVALID'}));
  });

  it.each([
    ['virtual-only section tail', 0x1250],
    ['zero-fill section with no raw bytes', 0x2800],
    ['last four bytes of image', 0x2ffc],
  ] as const)('accepts a four-byte TLS index in %s', (_label, rva) => {
    const bytes = tlsWithBssFixture(is64);
    setTlsPointer(bytes, is64, 2, base + BigInt(rva));
    const result = inspectPe(bytes);
    expect(result.tls_complete).toBe(true);
    expect(result.tls?.callbacks).toHaveLength(2);
    expect(result.diagnostics).toEqual([]);
  });

  it.each([
    ['crossing a virtual section boundary', 0x12fd],
    ['unmapped gap between sections', 0x1800],
    ['crossing image end', 0x2ffd],
    ['at image end', 0x3000],
    ['below image base', -1],
    ['crossing headers boundary', 0x1fe],
  ] as const)('rejects a TLS index %s', (_label, rva) => {
    const bytes = tlsWithBssFixture(is64);
    setTlsPointer(bytes, is64, 2, base + BigInt(rva));
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'TLS_DIRECTORY_INVALID'}));
  });

  it.each([
    ['at index start', 0x12fc],
    ['inside the index word', 0x12fe],
  ] as const)('rejects a virtual-only TLS index when another section begins %s', (_label, overlapRva) => {
    const bytes = tlsWithBssFixture(is64);
    const view = new DataView(bytes.buffer);
    const bss = 0x98 + (is64 ? 0xf0 : 0xe0) + 80;
    view.setUint32(bss + 8, 0x20, true);
    view.setUint32(bss + 12, overlapRva, true);
    setTlsPointer(bytes, is64, 2, base + 0x12fcn);
    const result = inspectPe(bytes);
    expect(result.tls).toBe(null);
    expect(result.tls_complete).toBe(false);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'TLS_DIRECTORY_INVALID'}));
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'SECTION_VIRTUAL_OVERLAP'}));
  });

  it('accepts an index ending exactly before a virtual overlap begins', () => {
    const bytes = tlsWithBssFixture(is64);
    const view = new DataView(bytes.buffer);
    const bss = 0x98 + (is64 ? 0xf0 : 0xe0) + 80;
    view.setUint32(bss + 8, 0x20, true);
    view.setUint32(bss + 12, 0x12fc, true);
    setTlsPointer(bytes, is64, 2, base + 0x12f8n);
    const result = inspectPe(bytes);
    expect(result.tls_complete).toBe(true);
    expect(result.tls?.callbacks).toHaveLength(2);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({code:'SECTION_VIRTUAL_OVERLAP'}));
  });
});
