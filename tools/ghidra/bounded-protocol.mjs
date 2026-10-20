import {isDeepStrictEqual} from 'node:util';
import {inspectPe} from '../../dist/src/pe.js';
import {sha256,requireThat} from './bounded-files.mjs';

const REQUEST='GHIDRA_REQUEST_INVALID',SUMMARY='GHIDRA_SUMMARY_INVALID';
const HASH=/^[a-f0-9]{64}$/;
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const integer=(value,low,high)=>Number.isSafeInteger(value)&&value>=low&&value<=high;
const keys=(value,expected)=>object(value)&&isDeepStrictEqual(Object.keys(value).sort(),[...expected].sort());
function address(value,code=SUMMARY) {
  requireThat(typeof value==='string'&&/^0x[0-9a-fA-F]{1,8}$/.test(value),code,'Expected a 32-bit hexadecimal address');
  return Number.parseInt(value.slice(2),16);
}
const sameAddress=(left,right)=>address(left)===address(right);
const labelFor=entry=>address(entry).toString(16).padStart(8,'0');

/** JSON.parse alone discards duplicate keys. This parser preserves that boundary. */
export function parseStrictJson(bytes,limit=4*1024*1024) {
  const fail=message=>requireThat(false,'GHIDRA_JSON_INVALID',message);
  requireThat(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=limit,
    'GHIDRA_JSON_INVALID','JSON byte budget exceeded');
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes); }
  catch { fail('JSON is not strict UTF-8'); }
  let at=0,nodes=0;
  const whitespace=()=>{while(/[\t\r\n ]/.test(text[at]??'!'))at++;};
  const string=()=>{
    const start=at++;let escaped=false;
    while(at<text.length) {
      const char=text[at++];
      if(!escaped&&char==='"') {
        try { return JSON.parse(text.slice(start,at)); } catch { fail('Invalid JSON string'); }
      }
      if(!escaped&&char==='\\')escaped=true;else escaped=false;
    }
    fail('Unterminated JSON string');
  };
  const value=depth=>{
    requireThat(depth<=64&&++nodes<=500000,'GHIDRA_JSON_INVALID','JSON structural budget exceeded');
    whitespace();const char=text[at];
    if(char==='"')return string();
    if(char==='{'||char==='[') {
      at++;const dictionary=char==='{',result=dictionary?{}:[],seen=new Set(),end=dictionary?'}':']';
      whitespace();if(text[at]===end){at++;return result;}
      while(at<text.length) {
        whitespace();let key;
        if(dictionary) {
          if(text[at]!== '"')fail('Expected a JSON object key');key=string();
          if(seen.has(key))fail('Duplicate JSON key');seen.add(key);whitespace();
          if(text[at++]!==':')fail('Missing JSON colon');
        }
        const item=value(depth+1);
        if(dictionary)Object.defineProperty(result,key,{value:item,enumerable:true,writable:true,configurable:true});else result.push(item);
        whitespace();const separator=text[at++];if(separator===end)return result;
        if(separator!==',')fail('Invalid JSON collection separator');
      }
      fail('Unterminated JSON collection');
    }
    for(const [literal,item] of [['true',true],['false',false],['null',null]])
      if(text.startsWith(literal,at)){at+=literal.length;return item;}
    const match=/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at));
    if(!match||match.index!==0)fail('Invalid JSON value');
    at+=match[0].length;const number=Number(match[0]);if(!Number.isFinite(number))fail('Nonfinite JSON number');return number;
  };
  const result=value(0);whitespace();if(at!==text.length)fail('Trailing JSON data');return result;
}

export function validateRequest(value) {
  requireThat(keys(value,['schema_version','expected_sha256','entries','decompile_seconds','script_seconds'])
    &&value.schema_version===1&&typeof value.expected_sha256==='string'&&HASH.test(value.expected_sha256)
    &&integer(value.decompile_seconds,1,5)&&integer(value.script_seconds,1,45)
    &&Array.isArray(value.entries)&&value.entries.length>=1&&value.entries.length<=5,
    REQUEST,'Invalid bounded request fields or budgets');
  const seen=new Set();
  for(const row of value.entries) {
    requireThat(keys(row,['va','max_bytes'])&&integer(row.max_bytes,1,2048),REQUEST,'Invalid entry fields or byte guard');
    const start=address(row.va,REQUEST);
    requireThat(!seen.has(start)&&start+row.max_bytes<=0x100000000,REQUEST,'Duplicate entry or overflowing guard');seen.add(start);
  }
  return value;
}

/** Uses the tested product PE inspector, adding only selected-range mapping. */
export function selectedPeBytes(input,request) {
  let inspection;
  try { inspection=inspectPe(input); }
  catch(error) { requireThat(false,'GHIDRA_INPUT_INVALID','Input PE preflight failed: '+error.message); }
  const base=BigInt(inspection.image_base);
  requireThat(base<=0xffffffffn,'GHIDRA_INPUT_INVALID','Selected VA32 analysis requires a 32-bit-addressable image base');
  const map=(va,size)=>{
    const start=va-Number(base),end=start+size;
    const overlapping=inspection.sections.filter(section=>section.rva<end
      &&section.rva+Math.max(section.virtual_size,section.raw_size)>start);
    requireThat(start>=0&&integer(size,1,2048)&&overlapping.length===1,'GHIDRA_INPUT_INVALID','Selected VA range is unmapped or ambiguous');
    const section=overlapping[0],offset=section.raw_offset+start-section.rva;
    requireThat((section.characteristics&0x20000000)!==0&&start>=section.rva
      &&end<=section.rva+Math.max(section.virtual_size,section.raw_size)
      &&end<=section.rva+section.raw_size&&offset>=0&&offset+size<=input.length,
      'GHIDRA_INPUT_INVALID','Selected guard requires unique executable, file-backed bytes');
    return input.subarray(offset,offset+size);
  };
  for(const row of request.entries)map(address(row.va,REQUEST),row.max_bytes);
  return {inspection,map};
}

const bodyContains=(ranges,pc)=>ranges.some(([start,end])=>start<=pc&&pc<end);
function mergedRanges(ranges) {
  const merged=[];
  for(const [start,end] of [...ranges].sort((a,b)=>a[0]-b[0])) {
    const last=merged.at(-1);
    requireThat(!last||start>=last[1],SUMMARY,'Listing instructions overlap');
    if(last&&start===last[1])last[1]=end;else merged.push([start,end]);
  }
  return merged;
}
function reportedRanges(value) {
  requireThat(Array.isArray(value)&&value.length<=2048,SUMMARY,'Invalid body ranges');
  return value.map(row=>{
    requireThat(keys(row,['start','end_inclusive']),SUMMARY,'Invalid range fields');
    const start=address(row.start),end=address(row.end_inclusive)+1;
    requireThat(end>start,SUMMARY,'Reversed body range');return [start,end];
  });
}

export async function validateSummary(summary,request,pe,readArtifact) {
  requireThat(keys(summary,['schema_version','provider','ghidra_version','input_sha256','language','compiler_spec',
    'image_base','auto_analysis','script_seconds','target_executed','request','functions','status','elapsed_script_ms'])
    &&summary.schema_version===1&&summary.provider==='ghidra-public-bounded-static'
    &&summary.input_sha256===request.expected_sha256&&summary.auto_analysis===false&&summary.target_executed===false
    &&summary.script_seconds===request.script_seconds&&isDeepStrictEqual(summary.request,request)
    &&BigInt(address(summary.image_base))===BigInt(pe.inspection.image_base)
    &&typeof summary.ghidra_version==='string'&&summary.ghidra_version.length<=256
    &&typeof summary.language==='string'&&typeof summary.compiler_spec==='string'
    &&integer(summary.elapsed_script_ms,0,120000)&&Array.isArray(summary.functions)
    &&summary.functions.length===request.entries.length,SUMMARY,'Summary identity, request, mode or denominator differs');
  const expected=new Map(request.entries.map(row=>[address(row.va),row])),seen=new Set(),results=[];
  const json=async name=>parseStrictJson(await readArtifact(name));
  for(const row of summary.functions) {
    requireThat(object(row),SUMMARY,'Invalid function observation');const entry=address(row.entry_va);
    requireThat(expected.has(entry)&&!seen.has(entry),SUMMARY,'Unexpected or repeated function entry');seen.add(entry);
    const selected=expected.get(entry),end=entry+selected.max_bytes,label=labelFor(row.entry_va);
    if(row.status==='failed') {
      requireThat(keys(row,['entry_va','status','error'])&&typeof row.error==='string'&&row.error.length<=8192,
        SUMMARY,'Invalid failed-function receipt');
      results.push({entry_va:row.entry_va,status:'failed',error:row.error,scope_accepted:false,accepted_c_file:null});continue;
    }
    requireThat(['observed','scope_rejected','decompile_incomplete'].includes(row.status)
      &&row.max_bytes===selected.max_bytes&&row.incremental_code_analysis===false
      &&HASH.test(row.guarded_bytes_sha256)&&row.guarded_bytes_sha256===sha256(pe.map(entry,selected.max_bytes))
      &&isDeepStrictEqual(reportedRanges(row.allowed_ranges),[[entry,end]])
      &&Array.isArray(row.listing)&&row.listing.length>=1&&row.listing.length<=2048
      &&row.instruction_count===row.listing.length,SUMMARY,'Function guard or listing metadata differs');
    const instructionRanges=[],addresses=new Set();
    for(const instruction of row.listing) {
      const start=address(instruction.va);
      requireThat(typeof instruction.bytes==='string'&&/^(?:[a-f0-9]{2}){1,2048}$/.test(instruction.bytes),
        SUMMARY,'Invalid instruction byte encoding');
      const bytes=Buffer.from(instruction.bytes,'hex'),finish=start+bytes.length;
      requireThat(!addresses.has(start)&&start>=entry&&finish<=end&&typeof instruction.text==='string'
        &&typeof instruction.flow_type==='string',SUMMARY,'Instruction lies outside the finite guard');addresses.add(start);
      requireThat(pe.map(start,bytes.length).equals(bytes),SUMMARY,'Listing bytes differ from staged PE bytes');
      instructionRanges.push([start,finish]);
    }
    const body=mergedRanges(instructionRanges);
    requireThat(bodyContains(body,entry)&&row.body_bytes===body.reduce((sum,[start,finish])=>sum+finish-start,0)
      &&isDeepStrictEqual(reportedRanges(row.body_ranges),body),SUMMARY,'Listing body accounting differs');
    requireThat(isDeepStrictEqual(await json(label+'.json'),row),SUMMARY,'Summary and per-entry JSON disagree');
    const raw=await json(label+'.pcode.json'),high=await json(label+'.high-pcode.json'),decomp=row.decompilation;
    requireThat(Array.isArray(raw)&&raw.length<=16384&&raw.length===row.raw_pcode_count
      &&Array.isArray(high)&&high.length<=16384&&object(decomp)&&high.length===decomp.high_pcode_count,
      SUMMARY,'P-code counts differ');
    for(const operation of raw)requireThat(object(operation)&&addresses.has(address(operation.pc)),SUMMARY,'Raw p-code PC is outside listing starts');
    const outside=[...new Set(high.map(operation=>{
      requireThat(object(operation),SUMMARY,'Invalid high-pcode operation');return address(operation.pc);
    }).filter(pc=>!bodyContains(body,pc)))].sort((a,b)=>a-b);
    requireThat(Array.isArray(decomp.outside_body_pcs)
      &&isDeepStrictEqual(decomp.outside_body_pcs.map(pc=>address(pc)),outside)
      &&decomp.scope_accepted===(outside.length===0)&&integer(decomp.timeout_seconds,1,request.decompile_seconds)
      &&typeof decomp.completed==='boolean'&&typeof decomp.timed_out==='boolean'&&typeof decomp.cancelled==='boolean',
      SUMMARY,'Actual high-pcode scope differs from reported acceptance');
    let accepted=null;
    if(row.status==='observed') {
      requireThat(outside.length===0&&decomp.completed&&!decomp.timed_out&&!decomp.cancelled
        &&decomp.c_file===label+'.c'&&!('unaccepted_c_file' in decomp),SUMMARY,'Observed C scope was not accepted');
      const c=await readArtifact(decomp.c_file,262144);
      new TextDecoder('utf-8',{fatal:true}).decode(c);requireThat(c.length>0,SUMMARY,'Empty accepted C output');accepted=decomp.c_file;
    } else if(row.status==='scope_rejected') {
      requireThat(outside.length>0&&row.error_code==='DECOMPILER_SCOPE_ESCAPE'&&!('c_file' in decomp)
        &&(!('unaccepted_c_file' in decomp)||decomp.unaccepted_c_file===label+'.scope-rejected.c'),
        SUMMARY,'Rejected C scope is inconsistent');
      if(decomp.unaccepted_c_file)new TextDecoder('utf-8',{fatal:true}).decode(await readArtifact(decomp.unaccepted_c_file,262144));
    } else requireThat(outside.length===0&&!('c_file' in decomp)&&!('unaccepted_c_file' in decomp),SUMMARY,'Incomplete C is incorrectly accepted');
    results.push({entry_va:row.entry_va,status:row.status,instruction_count:row.instruction_count,body_bytes:row.body_bytes,
      scope_accepted:outside.length===0,accepted_c_file:accepted,outside_body_pcs:decomp.outside_body_pcs,
      unknown_or_guard_exits:row.unknown_or_guard_exits,calls:row.calls,decompilation:decomp});
  }
  const status=results.every(row=>row.status==='observed')?'completed':'partial';
  requireThat(summary.status===status,SUMMARY,'Top-level status contradicts per-function observations');
  return {status,functions:results,ghidra_version:summary.ghidra_version,
    scope:'bounded static listing and decompiler-PC observations; function ABI, external dependencies and complete boundaries remain unverified'};
}
