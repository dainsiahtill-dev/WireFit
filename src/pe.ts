import { createHash } from 'node:crypto';

export interface PeDiagnostic { code: string; message: string }
export type PeImportSymbol = { name: string; hint: number } | { ordinal: number };
export interface PeImport { library: string; symbols: PeImportSymbol[] }
export interface PeString {
  /** Virtual address of the first byte. */
  va: string;
  rva: number;
  file_offset: number;
  encoding: 'ascii' | 'utf16le';
  length: number;
  text: string;
}
export interface PeExport {
  name: string | null;
  ordinal: number;
  rva: number;
  va: string;
  forwarder: string | null;
}
export interface PeSection {
  name: string;
  rva: number;
  virtual_size: number;
  raw_offset: number;
  raw_size: number;
  entropy: number;
  /** Entropy is computed on an evenly distributed sample for large sections. */
  entropy_sample_bytes: number;
  characteristics: number;
}
export interface PeEntryAssessment {
  kind: 'absent' | 'unmapped' | 'unclassified' | 'x86_seh_prolog_helper_like';
  /** A recognized byte pattern is only heuristic evidence, never an original-entry verdict. */
  basis: 'none' | 'heuristic';
  inspected_bytes: number;
}
export interface PeTlsCallback { va: string; rva: number; file_offset: number }
export interface PeTls {
  directory_rva: number;
  directory_size: number;
  start_address_of_raw_data: string;
  end_address_of_raw_data: string;
  address_of_index: string;
  address_of_callbacks: string;
  size_of_zero_fill: number;
  characteristics: number;
  callbacks: PeTlsCallback[];
}
export interface PeInspection {
  schema_version: 1;
  sha256: string;
  size_bytes: number;
  format: 'PE32' | 'PE32+';
  architecture: string;
  image_base: string;
  entry_point: { rva: number; va: string; file_offset: number | null; section: string | null; bytes_hex: string };
  entry_assessment: PeEntryAssessment;
  sections: PeSection[];
  /** Null means absent only when tls_complete is true; malformed TLS is discarded atomically. */
  tls: PeTls | null;
  tls_complete: boolean;
  imports: PeImport[];
  imports_complete: boolean;
  /** Printable strings found in the file backed parts of the image. */
  strings: PeString[];
  strings_complete: boolean;
  /** The sections whose string list hit the per section limit. */
  strings_truncated_sections: string[];
  /** The export directory, when the image exports symbols. */
  exports: PeExport[];
  exports_complete: boolean;
  diagnostics: PeDiagnostic[];
  indicators: { packed_suspected: boolean; reasons: string[] };
}

export class PeFormatError extends Error {
  readonly code = 'INVALID_PE';
  constructor(message: string) { super(message); this.name = 'PeFormatError'; }
}

const MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_SECTIONS = 96;
const MAX_IMPORT_DESCRIPTORS = 4096;
const MAX_IMPORT_SYMBOLS = 65536;
const MAX_STRING_BYTES = 4096;
const MAX_IMPORT_STRING_BYTES = 4 * 1024 * 1024;
const MAX_ENTROPY_SAMPLE_BYTES = 1024 * 1024;
const MAX_ENTRY_ASSESSMENT_BYTES = 64;
const MAX_TLS_CALLBACKS = 64;
const MAX_STRINGS_PER_SECTION = 20000;
const MAX_STRING_TEXT = 1024;
const MIN_STRING_LENGTH = 4;
const MAX_EXPORT_SYMBOLS = 65536;
const MAX_EXPORT_NAME_BYTES = 4096;
// push imm32; mov eax, fs:[0]; push eax; mov eax,[esp+10h];
// mov [esp+10h],ebp; lea ebp,[esp+10h]; sub esp,eax; push ebx.
const X86_SEH_PROLOG_SUFFIX = Uint8Array.from([
  0x64, 0xa1, 0, 0, 0, 0, 0x50, 0x8b, 0x44, 0x24, 0x10,
  0x89, 0x6c, 0x24, 0x10, 0x8d, 0x6c, 0x24, 0x10, 0x2b, 0xe0, 0x53,
]);
const RVA_LIMIT = 0x100000000;

function hasRange(total: number, offset: number, length: number): boolean {
  return Number.isSafeInteger(offset) && Number.isSafeInteger(length) && offset >= 0 && length >= 0 && offset <= total && length <= total - offset;
}

function hex(value: bigint): string { return `0x${value.toString(16)}`; }

function text(bytes: Uint8Array, offset: number, length: number): string {
  let result = '';
  for (let index = 0; index < length; index++) {
    const value = bytes[offset + index]!;
    if (value === 0) break;
    result += String.fromCharCode(value);
  }
  return result;
}

function entropy(bytes: Uint8Array, offset: number, length: number): { value: number; sampled: number } {
  if (length === 0) return { value: 0, sampled: 0 };
  const sampled = Math.min(length, MAX_ENTROPY_SAMPLE_BYTES);
  const frequencies = new Uint32Array(256);
  for (let index = 0; index < sampled; index++) {
    const position = offset + Math.floor(index * length / sampled);
    const value = bytes[position]!;
    frequencies[value] = frequencies[value]! + 1;
  }
  let value = 0;
  for (const count of frequencies) {
    if (count > 0) { const probability = count / sampled; value -= probability * Math.log2(probability); }
  }
  return { value, sampled };
}

interface VirtualRegion { section: PeSection; end: number; valid: boolean }
interface Mapping { offset: number; available: number }

/** Inspect an owned byte snapshot. This function never loads or executes the image. */
export function inspectPe(input: Uint8Array): PeInspection {
  if (!(input instanceof Uint8Array)) throw new PeFormatError('PE input must be a Uint8Array');
  if (input.byteLength < 64) throw new PeFormatError('Truncated DOS header');
  if (input.byteLength > MAX_FILE_BYTES) throw new PeFormatError(`PE input exceeds the ${MAX_FILE_BYTES} byte inspection limit`);
  // Both identity and interpretation use this copy, even when the caller supplied a Buffer/view.
  const bytes = new Uint8Array(input);
  const view = new DataView(bytes.buffer);
  const required = (offset: number, length: number, label: string) => {
    if (!hasRange(bytes.length, offset, length)) throw new PeFormatError(`Truncated or out-of-range ${label}`);
  };
  required(0, 64, 'DOS header');
  if (view.getUint16(0, true) !== 0x5a4d) throw new PeFormatError('Missing MZ signature');
  const pe = view.getUint32(0x3c, true);
  if (pe < 64) throw new PeFormatError('PE header overlaps the DOS header');
  required(pe, 24, 'PE/COFF header');
  if (view.getUint32(pe, true) !== 0x4550) throw new PeFormatError('Missing PE signature');
  const machine = view.getUint16(pe + 4, true);
  const sectionCount = view.getUint16(pe + 6, true);
  if (sectionCount === 0 || sectionCount > MAX_SECTIONS) throw new PeFormatError(`Section count must be between 1 and ${MAX_SECTIONS}`);
  const optionalSize = view.getUint16(pe + 20, true);
  const optional = pe + 24;
  required(optional, optionalSize, 'optional header');
  if (optionalSize < 2) throw new PeFormatError('Missing optional header magic');
  const magic = view.getUint16(optional, true);
  if (magic !== 0x10b && magic !== 0x20b) throw new PeFormatError('Unsupported PE optional header magic');
  const is64 = magic === 0x20b;
  const directoryOffset = is64 ? 112 : 96;
  if (optionalSize < directoryOffset) throw new PeFormatError('Optional header is shorter than its fixed fields');
  const sectionTable = optional + optionalSize;
  required(sectionTable, sectionCount * 40, 'section table');
  const imageBase = is64 ? view.getBigUint64(optional + 24, true) : BigInt(view.getUint32(optional + 28, true));
  const entryRva = view.getUint32(optional + 16, true);
  const imageSize = view.getUint32(optional + 56, true);
  const headersSize = view.getUint32(optional + 60, true);
  if (imageSize === 0) throw new PeFormatError('SizeOfImage must be nonzero');
  const addressLimit = 1n << BigInt(is64 ? 64 : 32);
  if (imageBase + BigInt(imageSize) > addressLimit) throw new PeFormatError('Image virtual address range overflows its address width');
  const diagnostics: PeDiagnostic[] = [];
  const addDiagnostic = (code: string, message: string) => { diagnostics.push({ code, message }); };
  const headersValid = headersSize >= sectionTable + sectionCount * 40 && headersSize <= bytes.length && headersSize <= imageSize;
  if (!headersValid) addDiagnostic('HEADER_SIZE_INVALID', 'SizeOfHeaders does not cover the section table within the file and image');
  const sections: PeSection[] = [];
  const regions: VirtualRegion[] = [];
  for (let index = 0; index < sectionCount; index++) {
    const offset = sectionTable + index * 40;
    const rawOffset = view.getUint32(offset + 20, true);
    const rawSize = view.getUint32(offset + 16, true);
    const availableRaw = rawOffset <= bytes.length ? Math.min(rawSize, bytes.length - rawOffset) : 0;
    const measured = entropy(bytes, rawOffset, availableRaw);
    const section: PeSection = {
      name: text(bytes, offset, 8), rva: view.getUint32(offset + 12, true),
      virtual_size: view.getUint32(offset + 8, true), raw_offset: rawOffset, raw_size: rawSize,
      entropy: measured.value, entropy_sample_bytes: measured.sampled, characteristics: view.getUint32(offset + 36, true),
    };
    sections.push(section);
    if (!hasRange(bytes.length, rawOffset, rawSize)) addDiagnostic('SECTION_RAW_TRUNCATED', `Section ${index} (${section.name}) raw range exceeds the file`);
    const extent = Math.max(section.virtual_size, section.raw_size);
    const end = section.rva + extent;
    const valid = hasRange(imageSize, section.rva, extent) && end <= RVA_LIMIT;
    if (!valid) addDiagnostic('SECTION_VIRTUAL_RANGE_INVALID', `Section ${index} (${section.name}) virtual range exceeds SizeOfImage`);
    if (headersValid && extent > 0 && section.rva < headersSize) addDiagnostic('SECTION_VIRTUAL_OVERLAP', `Section ${index} (${section.name}) overlaps mapped headers`);
    regions.push({ section, end, valid });
  }
  for (let left = 0; left < regions.length; left++) {
    const first = regions[left]!;
    for (let right = left + 1; right < regions.length; right++) {
      const second = regions[right]!;
      if (first.section.rva < first.end && second.section.rva < second.end && first.section.rva < second.end && second.section.rva < first.end) {
        addDiagnostic('SECTION_VIRTUAL_OVERLAP', `Sections ${left} and ${right} have overlapping virtual ranges`);
      }
    }
  }

  const matchingRegions = (rva: number) => regions.filter(region => rva >= region.section.rva && rva < region.end);
  const map = (rva: number, length = 1): Mapping | null => {
    if (!hasRange(imageSize, rva, length) || !hasRange(RVA_LIMIT, rva, length)) return null;
    const matches = matchingRegions(rva);
    const inHeaders = headersValid && rva < headersSize;
    if (matches.length + Number(inHeaders) !== 1) return null;
    if (inHeaders) {
      let available = headersSize - rva;
      for (const region of regions) {
        if (region.end > region.section.rva && region.section.rva > rva) available = Math.min(available, region.section.rva - rva);
      }
      return length <= available ? { offset: rva, available } : null;
    }
    const region = matches[0]!;
    if (!region.valid) return null;
    const section = region.section;
    const delta = rva - section.rva;
    if (length > region.end - rva || !hasRange(section.raw_size, delta, length)) return null;
    const offset = section.raw_offset + delta;
    if (!hasRange(bytes.length, offset, length)) return null;
    // Another virtual range may begin before the current section ends.
    let available = Math.min(section.raw_size - delta, region.end - rva, bytes.length - offset);
    for (const other of regions) {
      if (other !== region && other.end > other.section.rva && other.section.rva > rva) available = Math.min(available, other.section.rva - rva);
    }
    return length <= available ? { offset, available } : null;
  };

  // Loader-written storage can live in zero-fill memory without corresponding file bytes.
  const hasUniqueVirtualRange = (rva: number, length: number): boolean => {
    if (!hasRange(imageSize, rva, length) || !hasRange(RVA_LIMIT, rva, length)) return false;
    const matches = matchingRegions(rva);
    const inHeaders = headersValid && rva < headersSize;
    if (matches.length + Number(inHeaders) !== 1) return false;
    const region = matches[0];
    if (!inHeaders && !region?.valid) return false;
    const end = rva + length;
    if (end > (inHeaders ? headersSize : region!.end)) return false;
    // Checking only the first byte would miss a second region starting inside the word.
    return regions.every(other => other === region || other.end <= other.section.rva
      || other.section.rva >= end || other.end <= rva);
  };

  const entryMapping = entryRva === 0 ? null : map(entryRva);
  const entrySections = matchingRegions(entryRva);
  const entrySection = entrySections.length === 1 ? entrySections[0]!.section.name : null;
  let entryBytes = '';
  if (entryMapping) {
    for (const byte of bytes.subarray(entryMapping.offset, entryMapping.offset + Math.min(16, entryMapping.available))) entryBytes += byte.toString(16).padStart(2, '0');
  } else if (entryRva !== 0) addDiagnostic('ENTRY_POINT_NOT_FILE_BACKED', 'Entry point does not map unambiguously to available file bytes');

  const inspectedEntryBytes = entryMapping ? Math.min(MAX_ENTRY_ASSESSMENT_BYTES, entryMapping.available) : 0;
  const entryAssessment: PeEntryAssessment = {
    kind: entryRva === 0 ? 'absent' : entryMapping ? 'unclassified' : 'unmapped',
    basis: 'none', inspected_bytes: inspectedEntryBytes,
  };
  if (machine === 0x14c && !is64 && entryMapping && inspectedEntryBytes >= 5 + X86_SEH_PROLOG_SUFFIX.length
    && bytes[entryMapping.offset] === 0x68
    && X86_SEH_PROLOG_SUFFIX.every((value, index) => bytes[entryMapping.offset + 5 + index] === value)) {
    entryAssessment.kind = 'x86_seh_prolog_helper_like';
    entryAssessment.basis = 'heuristic';
    addDiagnostic('ENTRY_POINT_SEH_PROLOG_HEURISTIC', 'Declared x86 entry resembles an SEH prolog helper; this heuristic does not identify the original entry point or establish runnable startup');
  }

  const directoryCount = view.getUint32(optional + directoryOffset - 4, true);
  const directoryCapacity = Math.floor((optionalSize - directoryOffset) / 8);
  const validDirectoryCount = directoryCount <= directoryCapacity && directoryCount <= 16;
  if (!validDirectoryCount) addDiagnostic('DIRECTORY_COUNT_INVALID', 'NumberOfRvaAndSizes exceeds the optional header or supported standard directory count');
  let imports: PeImport[] = [];
  let importsComplete = true;
  if (!validDirectoryCount) importsComplete = false;
  else if (directoryCount > 1) {
    const directory = optional + directoryOffset + 8;
    const importRva = view.getUint32(directory, true);
    const importSize = view.getUint32(directory + 4, true);
    if (importRva !== 0 || importSize !== 0) {
      try { imports = parseImports(importRva, importSize); }
      catch (error) {
        if (!(error instanceof ImportParseError)) throw error;
        imports = [];
        importsComplete = false;
        addDiagnostic('IMPORT_DIRECTORY_INVALID', error.message);
      }
    }
  }

  let tls: PeTls | null = null;
  let tlsComplete = validDirectoryCount;
  if (validDirectoryCount && directoryCount > 9) {
    const directory = optional + directoryOffset + 9 * 8;
    const tlsRva = view.getUint32(directory, true);
    const tlsSize = view.getUint32(directory + 4, true);
    if (tlsRva !== 0 || tlsSize !== 0) {
      try { tls = parseTls(tlsRva, tlsSize); }
      catch (error) {
        if (!(error instanceof TlsParseError)) throw error;
        tlsComplete = false;
        addDiagnostic('TLS_DIRECTORY_INVALID', error.message);
      }
    }
  }

  function parseTls(rva: number, size: number): PeTls {
    const invalid = (message: string): never => { throw new TlsParseError(message); };
    const width = is64 ? 8 : 4;
    const minimumSize = is64 ? 40 : 24;
    if (rva === 0 || size < minimumSize) return invalid('TLS directory has an invalid RVA or fixed-field size');
    const directory = map(rva, size);
    if (!directory) return invalid('TLS directory does not map entirely to unambiguous file-backed image data');
    const pointer = (offset: number) => is64 ? view.getBigUint64(offset, true) : BigInt(view.getUint32(offset, true));
    const start = pointer(directory.offset);
    const end = pointer(directory.offset + width);
    const indexAddress = pointer(directory.offset + width * 2);
    const callbacksAddress = pointer(directory.offset + width * 3);
    // Check VAs as bigint before converting the proven 32-bit RVA to number.
    const vaToRva = (value: bigint, length: number, label: string): number => {
      const delta = value - imageBase;
      if (delta < 0n || delta > BigInt(imageSize) || delta >= BigInt(RVA_LIMIT)
        || !hasRange(imageSize, Number(delta), length)) return invalid(`${label} VA ${hex(value)} is outside the image`);
      return Number(delta);
    };
    const mapVa = (value: bigint, length: number, label: string): { rva: number; mapping: Mapping } => {
      const addressRva = vaToRva(value, length, label);
      const mapping = map(addressRva, length);
      if (!mapping) return invalid(`${label} VA ${hex(value)} does not map to unambiguous file-backed image data`);
      return { rva: addressRva, mapping };
    };
    if (start !== 0n || end !== 0n) {
      if (start === 0n || end === 0n || end < start || end > imageBase + BigInt(imageSize)) return invalid(`TLS raw template has invalid VA endpoints ${hex(start)} through ${hex(end)}`);
      if (start === end) vaToRva(start, 0, 'TLS empty raw template');
      else mapVa(start, Number(end - start), 'TLS raw template');
    }
    if (indexAddress !== 0n) {
      const indexRva = vaToRva(indexAddress, 4, 'TLS index');
      if (!hasUniqueVirtualRange(indexRva, 4)) return invalid(`TLS index VA ${hex(indexAddress)} does not map to unambiguous virtual image storage`);
    }
    const callbacks: PeTlsCallback[] = [];
    if (callbacksAddress !== 0n) {
      const first = mapVa(callbacksAddress, width, 'TLS callback array');
      let terminated = false;
      for (let slot = 0; slot <= MAX_TLS_CALLBACKS; slot++) {
        const item = map(first.rva + slot * width, width);
        if (!item) return invalid('TLS callback array is not terminated within file-backed image data');
        const value = pointer(item.offset);
        if (value === 0n) { terminated = true; break; }
        if (slot === MAX_TLS_CALLBACKS) return invalid('TLS callback count exceeds the inspection limit');
        const target = mapVa(value, 1, 'TLS callback');
        callbacks.push({ va: hex(value), rva: target.rva, file_offset: target.mapping.offset });
      }
      if (!terminated) return invalid('TLS callback array has no terminator within the inspection limit');
    }
    return {
      directory_rva: rva, directory_size: size,
      start_address_of_raw_data: hex(start), end_address_of_raw_data: hex(end),
      address_of_index: hex(indexAddress), address_of_callbacks: hex(callbacksAddress),
      size_of_zero_fill: view.getUint32(directory.offset + width * 4, true),
      characteristics: view.getUint32(directory.offset + width * 4 + 4, true), callbacks,
    };
  }

  function parseImports(rva: number, size: number): PeImport[] {
    const invalid = (message: string): never => { throw new ImportParseError(message); };
    if (rva === 0 || size < 20 || !hasRange(imageSize, rva, size) || !hasRange(RVA_LIMIT, rva, size)) invalid('Import directory has an invalid RVA or size');
    const result: PeImport[] = [];
    const thunkWidth = is64 ? 8 : 4;
    const ordinalFlag = is64 ? 0x8000000000000000n : 0x80000000n;
    let symbolsRead = 0;
    let stringBytesRead = 0;
    const readString = (stringRva: number): string => {
      const mapping = map(stringRva);
      if (!mapping) return invalid('Import name does not map to file-backed data');
      const bound = Math.min(mapping.available, MAX_STRING_BYTES);
      let value = '';
      for (let index = 0; index < bound; index++) {
        if (++stringBytesRead > MAX_IMPORT_STRING_BYTES) return invalid('Import strings exceed the inspection byte budget');
        const byte = bytes[mapping.offset + index]!;
        if (byte === 0) {
          if (value.length === 0) return invalid('Import name is empty');
          return value;
        }
        if (byte < 0x20 || byte > 0x7e) return invalid('Import name contains a non-printable ASCII byte');
        value += String.fromCharCode(byte);
      }
      return invalid('Import name is not terminated within its mapped region and length limit');
    };
    for (let index = 0; index < MAX_IMPORT_DESCRIPTORS && index * 20 + 20 <= size; index++) {
      const descriptor = map(rva + index * 20, 20);
      if (!descriptor) return invalid('Import descriptor does not map to file-backed data');
      const originalThunk = view.getUint32(descriptor.offset, true);
      const timestamp = view.getUint32(descriptor.offset + 4, true);
      const forwarderChain = view.getUint32(descriptor.offset + 8, true);
      const nameRva = view.getUint32(descriptor.offset + 12, true);
      const firstThunk = view.getUint32(descriptor.offset + 16, true);
      if (originalThunk === 0 && timestamp === 0 && forwarderChain === 0 && nameRva === 0 && firstThunk === 0) return result;
      if (nameRva === 0 || firstThunk === 0) return invalid('Import descriptor is missing a library name or address table');
      const library = readString(nameRva);
      const thunkRva = originalThunk || firstThunk;
      const symbols: PeImportSymbol[] = [];
      let terminated = false;
      for (let slot = 0; slot <= MAX_IMPORT_SYMBOLS; slot++) {
        const thunk = map(thunkRva + slot * thunkWidth, thunkWidth);
        if (!thunk) return invalid('Import thunk does not map to file-backed data');
        const value = is64 ? view.getBigUint64(thunk.offset, true) : BigInt(view.getUint32(thunk.offset, true));
        if (value === 0n) { terminated = true; break; }
        if (++symbolsRead > MAX_IMPORT_SYMBOLS) return invalid('Import symbol count exceeds the inspection limit');
        if ((value & ordinalFlag) !== 0n) {
          if ((value & ~(ordinalFlag | 0xffffn)) !== 0n) return invalid('Ordinal thunk has nonzero reserved bits');
          symbols.push({ ordinal: Number(value & 0xffffn) });
        } else {
          if (value > 0x7fffffffn) return invalid('Import name thunk exceeds its 31-bit RVA field');
          const name = Number(value);
          const hint = map(name, 2);
          if (!hint) return invalid('Import hint does not map to file-backed data');
          symbols.push({ name: readString(name + 2), hint: view.getUint16(hint.offset, true) });
        }
      }
      if (!terminated) return invalid('Import thunk table has no terminator within its inspection limit');
      result.push({ library, symbols });
    }
    return invalid('Import descriptor table has no terminator within its declared size and inspection limit');
  }

  /*
   * Printable strings.
   *
   * A triage tool without strings is blind, so the image is scanned for
   * printable ASCII and for UTF-16LE runs. Only file backed section bytes are
   * scanned and every string keeps its file offset, its RVA and its virtual
   * address so a reader can jump straight to the reference.
   */
  const printable=(value:number):boolean=>value>=0x20&&value<=0x7e;
  const strings:PeString[]=[];
  const truncatedSections:string[]=[];
  let stringsComplete=true;
  for (const section of sections) {
    if (section.raw_size===0||section.raw_offset+section.raw_size>bytes.length)continue;
    const end=section.raw_offset+section.raw_size;
    let offset=section.raw_offset;
    let sectionStrings=0;
    while (offset<end) {
      if (sectionStrings>=MAX_STRINGS_PER_SECTION){
        // A section that hits the limit is truncated on its own, so a data
        // section is never crowded out by the code section before it.
        stringsComplete=false;
        truncatedSections.push(section.name);
        break;
      }
      // A UTF-16LE run is a printable byte followed by a zero byte.
      if (offset+1<end&&printable(bytes[offset]!)&&bytes[offset+1]===0) {
        let length=0;
        while (offset+length*2+1<end&&printable(bytes[offset+length*2]!)&&bytes[offset+length*2+1]===0)length++;
        if (length>=MIN_STRING_LENGTH) {
          const text=String.fromCharCode(...Array.from({length:Math.min(length,MAX_STRING_TEXT)},(_,index)=>bytes[offset+index*2]!));
          strings.push({va:hex(imageBase+BigInt(section.rva+(offset-section.raw_offset))),rva:section.rva+(offset-section.raw_offset),file_offset:offset,encoding:'utf16le',length,text});
          sectionStrings++;
          offset+=length*2;
          continue;
        }
      }
      if (printable(bytes[offset]!)) {
        let length=0;
        while (offset+length<end&&printable(bytes[offset+length]!))length++;
        if (length>=MIN_STRING_LENGTH) {
          const text=String.fromCharCode(...Array.from({length:Math.min(length,MAX_STRING_TEXT)},(_,index)=>bytes[offset+index]!));
          strings.push({va:hex(imageBase+BigInt(section.rva+(offset-section.raw_offset))),rva:section.rva+(offset-section.raw_offset),file_offset:offset,encoding:'ascii',length,text});
          sectionStrings++;
          offset+=length;
          continue;
        }
      }
      offset++;
    }
  }

  /*
   * The export directory.
   *
   * An image that exports symbols is a library, and the exported names are
   * often the fastest route into what a library actually does.
   */
  const exports:PeExport[]=[];
  let exportsComplete=true;
  const readExportName=(stringRva:number):string|null=>{
    const nameMapping=map(stringRva,1);
    if(!nameMapping)return null;
    let value='';
    for(let index=0;index<MAX_EXPORT_NAME_BYTES&&nameMapping.offset+index<bytes.length;index++){
      const byte=bytes[nameMapping.offset+index]!;
      if(byte===0)return value.length>0?value:null;
      if(byte<0x20||byte>0x7e)return null;
      value+=String.fromCharCode(byte);
    }
    return null;
  };
  let exportDirectory:{rva:number;size:number}|null=null;
  if (validDirectoryCount&&directoryCount>0) {
    const directory=optional+directoryOffset;
    const exportRva=view.getUint32(directory,true);
    const exportSize=view.getUint32(directory+4,true);
    if (exportRva!==0||exportSize!==0)exportDirectory={rva:exportRva,size:exportSize};
  }
  if (exportDirectory!==null&&exportDirectory.rva!==0&&exportDirectory.size>0) {
    const mapping=map(exportDirectory.rva,40);
    if(!mapping){exportsComplete=false;addDiagnostic('EXPORT_DIRECTORY_INVALID','Export directory does not map to file backed data');}
    else {
      const base=mapping.offset;
      const nameRva=view.getUint32(base+12,true);
      const ordinalBase=view.getUint32(base+16,true);
      const functionCount=view.getUint32(base+20,true);
      const nameCount=view.getUint32(base+24,true);
      const functionsRva=view.getUint32(base+28,true);
      const namesRva=view.getUint32(base+32,true);
      const ordinalsRva=view.getUint32(base+36,true);
      if (functionCount>MAX_EXPORT_SYMBOLS||nameCount>MAX_EXPORT_SYMBOLS){exportsComplete=false;addDiagnostic('EXPORT_DIRECTORY_INVALID','Export symbol count exceeds the inspection limit');}
      else {
        const functionTable=functionsRva===0?null:map(functionsRva,functionCount*4);
        const nameTable=nameCount===0||namesRva===0?null:map(namesRva,nameCount*4);
        const ordinalTable=nameCount===0||ordinalsRva===0?null:map(ordinalsRva,nameCount*2);
        if (functionCount>0&&(functionTable===null||(nameCount>0&&(nameTable===null||ordinalTable===null)))){
          exportsComplete=false;addDiagnostic('EXPORT_DIRECTORY_INVALID','Export tables do not map to file backed data');
        }else if (functionTable!==null){
          const names=new Map<number,string>();
          if (nameTable!==null&&ordinalTable!==null){
            for (let index=0;index<nameCount;index++){
              const namePointer=view.getUint32(nameTable.offset+index*4,true);
              const ordinal=view.getUint16(ordinalTable.offset+index*2,true);
              const text=readExportName(namePointer);
              if (text!==null)names.set(ordinal,text);
            }
          }
          for (let index=0;index<functionCount;index++){
            const rva=view.getUint32(functionTable.offset+index*4,true);
            if (rva===0)continue;
            const forwarder=exportDirectory.rva<=rva&&rva<exportDirectory.rva+exportDirectory.size?readExportName(rva):null;
            exports.push({name:names.get(index)??null,ordinal:ordinalBase+index,rva,va:hex(imageBase+BigInt(rva)),forwarder});
          }
        }
      }
    }
  }

  const reasons: string[] = [];
  let highEntropy = false;
  let writableExecutable = false;
  for (const section of sections) {
    if (section.entropy_sample_bytes >= 512 && section.entropy >= 7.2) {
      highEntropy = true;
      reasons.push(`Section ${section.name} has high raw-byte entropy (${section.entropy.toFixed(3)} bits per byte)`);
    }
    if ((section.characteristics & 0x80000000) !== 0 && (section.characteristics & 0x20000000) !== 0) {
      writableExecutable = true;
      reasons.push(`Section ${section.name} is writable and executable`);
    }
  }
  const architectures: Record<number, string> = { 0x14c: 'x86', 0x8664: 'x86_64', 0x1c0: 'arm', 0x1c4: 'armv7', 0xaa64: 'aarch64', 0xa641: 'arm64ec', 0x200: 'ia64' };
  return {
    schema_version: 1, sha256: createHash('sha256').update(bytes).digest('hex'), size_bytes: bytes.length,
    format: is64 ? 'PE32+' : 'PE32', architecture: architectures[machine] ?? `unknown_0x${machine.toString(16)}`,
    image_base: hex(imageBase), entry_point: { rva: entryRva, va: hex(imageBase + BigInt(entryRva)), file_offset: entryMapping?.offset ?? null, section: entrySection, bytes_hex: entryBytes },
    entry_assessment: entryAssessment, sections, tls, tls_complete: tlsComplete, imports, imports_complete: importsComplete,
    strings, strings_complete: stringsComplete, strings_truncated_sections: truncatedSections,
    exports, exports_complete: exportsComplete, diagnostics,
    indicators: { packed_suspected: highEntropy && writableExecutable, reasons },
  };
}

class ImportParseError extends Error {}
class TlsParseError extends Error {}

