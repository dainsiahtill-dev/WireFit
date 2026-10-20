import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
const api = await import('./agent-variant.mjs').catch(error => {
  if(error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
  return {};
});
const instrument = source => {
  assert.equal(typeof api.instrumentAgent,'function','instrumentAgent is not implemented');
  return api.instrumentAgent(source);
};
const original = readFileSync(new URL('../native-trace/agent.js',import.meta.url));
const decode = bytes => new TextDecoder('utf-8',{fatal:true}).decode(bytes);
const SHA = bytes => createHash('sha256').update(bytes).digest('hex');
const SOURCE_SHA='e98e21e5e6922560db05326d78b391f101a390f00841e1106750a8bc0b572e4d';
const MARKER='wirefit_export_predicate_v1=';
const GUARD='            if (exported === undefined || exported.type !== "function" || range === null || !range.protection.includes("x")) {\n';
const OLD_BODY='                throw new Error("Requested export is not an executable function");\n';
function run(source,options={}) {
  const calls=[],messages=[];
  const pointer=value=>({toString(){return value;}});
  const target=options.missingTarget?null:pointer(options.target??'0x671cdbf0');
  const exported=options.missingExport?undefined:{name:'requested',type:options.type??'function',address:pointer('0x671cdbf0')};
  if(options.addressThrows && exported)Object.defineProperty(exported,'address',{get(){throw new Error('diagnostic getter');}});
  if(options.addressText && exported)exported.address=pointer(options.addressText);
  const range=options.nullRange?null:{base:pointer(options.base??'0x671cd000'),size:options.size??4096,protection:options.protection??'r-x'};
  const module={findExportByName(name){calls.push(['findExport',name]);return target;},
    enumerateExports(){calls.push(['enumerateExports']);return exported===undefined?[]:[exported];}};
  const sandbox={rpc:{},send:value=>messages.push(JSON.parse(JSON.stringify(value))),Process:{
    findModuleByName(name){calls.push(['findModule',name]);return options.unloaded?null:module;},
    findRangeByAddress(value){calls.push(['findRange',value===target]);return range;},
  },Interceptor:{attach(value,callbacks){calls.push(['attach',value===target,typeof callbacks.onEnter]);return {detach(){}};}}};
  vm.createContext(sandbox,{codeGeneration:{strings:false,wasm:false}});
  vm.runInContext(decode(source)+'\nconfig={max_events:16,api_hooks:[{module:"QtCore4.dll",symbol:"requested"}]};'+
    'hookStates=[{module:"QtCore4.dll",symbol:"requested",status:"pending_module",address:null,error:null,observations:0}];'+
    'installHooks();globalThis.observation={states:copyHookStates(),hookCount:hooks.size};',sandbox,{timeout:100});
  return {calls,messages,observation:JSON.parse(JSON.stringify(sandbox.observation))};
}
function diagnostic(value){const text=value.observation.states[0].error;assert.ok(text.includes(MARKER));return JSON.parse(text.slice(text.indexOf(MARKER)+MARKER.length));}
function reject(source){assert.throws(()=>instrument(source),error=>error.code==='AGENT_VARIANT_SOURCE_INVALID');}

test('pins the source and describes a distinct deterministic diagnostic variant',()=>{
  assert.equal(SHA(original),SOURCE_SHA);const one=instrument(original),two=instrument(original);
  assert.ok(Buffer.isBuffer(one.bytes));assert.equal(one.source_sha256,SOURCE_SHA);assert.equal(one.diagnostic_marker,MARKER);
  assert.equal(one.sha256,SHA(one.bytes));assert.notEqual(one.sha256,SOURCE_SHA);assert.deepEqual(one.bytes,two.bytes);
});
test('only the single throw body changes; all other slices and the exact guard remain identical',()=>{
  const old=decode(original),next=decode(instrument(original).bytes),start=old.indexOf(GUARD)+GUARD.length;
  assert.ok(start>=GUARD.length);assert.equal(old.split(GUARD).length,2);
  assert.equal(next.slice(0,start),old.slice(0,start));
  const end=old.indexOf(OLD_BODY,start)+OLD_BODY.length;
  assert.ok(next.endsWith(old.slice(end)));assert.equal(next.split(GUARD).length,2);
  const suffixStart=next.length-old.slice(end).length;
  assert.equal(next.slice(suffixStart),old.slice(end));
  assert.equal(next.slice(start,suffixStart).includes('Process.'),false);
  assert.equal(next.slice(start,suffixStart).includes('Interceptor.'),false);
});
test('unknown identities, altered/duplicated anchors and invalid UTF-8/bounds are rejected',async t=>{
  for(const [name,bytes] of [
    ['other identity',Buffer.from(decode(original).replace('"use strict"','"use strict "'),'utf8')],
    ['missing anchor',Buffer.from(decode(original).replace(GUARD,''),'utf8')],
    ['duplicate anchor',Buffer.concat([original,Buffer.from(GUARD,'utf8')])],
    ['invalid UTF-8',Buffer.concat([Buffer.from([0xff]),original.subarray(1)])],['empty',Buffer.alloc(0)],['oversize',Buffer.alloc(65537)],
    ['non Buffer',new Uint8Array(original)],
  ])await t.test(name,()=>reject(bytes));
});
test('valid executable functions attach exactly as before without diagnostics',()=>{
  const old=run(original),next=run(instrument(original).bytes);
  assert.deepEqual(next,old);assert.equal(next.observation.hookCount,1);
});
test('guard combinations preserve the original decision and native-API call order',async t=>{
  for(const options of [
    {type:'variable'},{missingExport:true},{nullRange:true},{protection:'rw-'},
    {type:'variable',nullRange:true},{missingExport:true,protection:'---'},
    {type:'function',protection:'rwx'},{type:'function',protection:'--x'},
  ])await t.test(JSON.stringify(options),()=>{
    const old=run(original,options),next=run(instrument(original).bytes,options);
    assert.deepEqual(next.calls,old.calls);assert.equal(next.observation.hookCount,old.observation.hookCount);
    assert.equal(next.observation.states[0].status,old.observation.states[0].status);
    if(old.observation.hookCount===0){
      assert.match(next.observation.states[0].error,/Requested export is not an executable function/);
      const d=diagnostic(next);assert.equal(d.export_present,!options.missingExport);
      assert.equal(d.export_type,options.missingExport?null:options.type??'function');
      assert.equal(d.range_present,!options.nullRange);assert.equal(d.range_protection,options.nullRange?null:options.protection??'r-x');
    }
  });
});
test('diagnostic reports already-obtained target/export/range metadata with no reads',()=>{
  const next=run(instrument(original).bytes,{type:'variable'});
  assert.deepEqual(diagnostic(next),{target:'0x671cdbf0',export_present:true,export_type:'variable',export_address:'0x671cdbf0',
    range_present:true,range_base:'0x671cd000',range_size:4096,range_protection:'r-x'});
  assert.equal(next.calls.filter(row=>row[0]==='findRange').length,1);
});
test('missing target and unloaded module follow unchanged earlier lifecycle branches',async t=>{
  for(const options of [{missingTarget:true},{unloaded:true}])await t.test(JSON.stringify(options),()=>{
    assert.deepEqual(run(instrument(original).bytes,options),run(original,options));
  });
});
test('formatting failures preserve original guard error and a bounded machine-readable fallback',()=>{
  const next=run(instrument(original).bytes,{type:'variable',addressThrows:true});
  assert.equal(next.observation.hookCount,0);assert.match(next.observation.states[0].error,/Requested export is not an executable function/);
  assert.deepEqual(diagnostic(next),{diagnostic_error:'diagnostic_build_failed'});
});
test('hostile metadata cannot exceed the UTF-8 error budget or break JSON framing',()=>{
  const next=run(instrument(original).bytes,{type:'\u0001'.repeat(5000),target:'😀'.repeat(5000),
    addressText:'\\"\n'.repeat(5000),base:'\u0002'.repeat(5000),protection:'\u0003'.repeat(5000),size:Infinity});
  diagnostic(next);
  assert.ok(Buffer.byteLength(next.observation.states[0].error,'utf8')<2048);
  for(const message of next.messages)if(message.kind==='fatal')assert.ok(Buffer.byteLength(message.message,'utf8')<2048);
});
