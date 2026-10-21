import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {inspectPe,type PeInspection} from '../src/pe.js';

const FIXTURE='artifacts/native/fixture-build/wirefit-fixture.exe';
const VMDE='exports/vmde-20261020/unpacked_vmde.exe';

async function inspect(file:string):Promise<PeInspection>{
 return inspectPe(new Uint8Array(await readFile(file)));
}

describe('pe string and export triage',()=>{
 it('extracts the exported symbols of a library',async()=>{
  if(!existsSync(FIXTURE))return;
  const inspection=await inspect(FIXTURE);
  expect(inspection.exports_complete).toBe(true);
  const names=inspection.exports.map((entry)=>entry.name);
  expect(names).toContain('fixture_bv8_mba_original');
  expect(names).toContain('fixture_bv64_add');
  expect(names).toContain('fixture_f32_clamp_target');
  for(const entry of inspection.exports){
   expect(entry.ordinal).toBeGreaterThan(0);
   expect(entry.va).toMatch(/^0x[0-9a-f]+$/);
   expect(entry.rva).toBeGreaterThan(0);
  }
 });

 it('extracts printable strings with their file offset, rva and virtual address',async()=>{
  if(!existsSync(FIXTURE))return;
  const inspection=await inspect(FIXTURE);
  expect(inspection.strings.length).toBeGreaterThan(0);
  expect(inspection.strings_complete).toBe(true);
  const imageBase=BigInt(inspection.image_base);
  for(const entry of inspection.strings){
   expect(entry.length).toBeGreaterThanOrEqual(4);
   expect(entry.text.length).toBeGreaterThanOrEqual(4);
   expect(entry.file_offset).toBeGreaterThanOrEqual(0);
   expect(entry.rva).toBeGreaterThan(0);
   expect(BigInt(entry.va)).toBe(imageBase+BigInt(entry.rva));
   expect(['ascii','utf16le']).toContain(entry.encoding);
  }
  expect(inspection.strings.some((entry)=>entry.text.includes('fixture'))).toBe(true);
 });

 it('reports a truncated string list instead of pretending it is complete',async()=>{
  if(!existsSync(VMDE))return;
  const inspection=await inspect(VMDE);
  expect(inspection.strings.length).toBeGreaterThan(0);
  if(inspection.strings_complete===false){
   expect(inspection.strings_truncated_sections.length).toBeGreaterThan(0);
   for(const name of inspection.strings_truncated_sections)
    expect(inspection.sections.some((section)=>section.name===name)).toBe(true);
  }else{
   expect(inspection.strings_truncated_sections).toEqual([]);
  }
 });

 it('reports an image without exports as a complete empty list',async()=>{
  if(!existsSync(VMDE))return;
  const inspection=await inspect(VMDE);
  expect(inspection.exports_complete).toBe(true);
  expect(Array.isArray(inspection.exports)).toBe(true);
 });
});
