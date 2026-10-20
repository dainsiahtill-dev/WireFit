import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,mkdir,readFile,realpath,rm,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {loadNativeStatus} from '../src/native-status.js';

const owned:string[]=[];
afterEach(async()=>{
 for(const directory of owned.splice(0)){
  const resolved=await realpath(directory);const temporaryRoot=await realpath(tmpdir());
  if(path.dirname(resolved)!==temporaryRoot||!path.basename(resolved).startsWith('wirefit-native-status-'))throw new Error('Refusing cleanup outside owned temporary directory');
  await rm(resolved,{recursive:true,force:true});
 }
});
async function fixture(){
 const root=await mkdtemp(path.join(tmpdir(),'wirefit-native-status-'));owned.push(root);
 const save=async(relative:string,value:unknown)=>{const file=path.join(root,relative);await mkdir(path.dirname(file),{recursive:true});await writeFile(file,typeof value==='string'?value:JSON.stringify(value),'utf8');};
 const identity=async(relative:string)=>{const bytes=await readFile(path.join(root,relative));return {path:relative,sha256:createHash('sha256').update(bytes).digest('hex'),size_bytes:bytes.length};};
 const javaHome=path.join(root,'tools/jdk');const ghidraHome=path.join(root,'tools/ghidra');
 const java=path.join(javaHome,'bin',process.platform==='win32'?'java.exe':'java');const javac=path.join(javaHome,'bin',process.platform==='win32'?'javac.exe':'javac');
 const headless=path.join(ghidraHome,'support',process.platform==='win32'?'analyzeHeadless.bat':'analyzeHeadless');
 for(const file of [java,javac,headless,path.join(root,'tools/node'),path.join(root,'tools/rea.mjs')])await save(path.relative(root,file),'fixture; never execute');
 await save('.local/rea-native.json',{command:path.join(root,'tools/node'),args:[path.join(root,'tools/rea.mjs'),'--mcp'],env:{JAVA_HOME:javaHome,GHIDRA_INSTALL_DIR:ghidraHome}});
 await save('fixtures/target.exe','recorded target bytes');const target=await identity('fixtures/target.exe');
 const flow={available:true,provenance:'ghidra-high-pcode',operations:[{id:'value'}],def_use:[],truncated:false,known_omitted_edges:0,known_omitted_inputs:0,omitted_operations_lower_bound:0};
 await save('artifacts/native/native-evidence.json',{records:[{operation:'analyze_function',evidence_id:'ev_fixture',provider:{id:'ghidra',version:'12.1.4'},subject:{local_path:path.join(root,target.path),digest:{sha256:target.sha256}},normalized_result:{pseudocode:'int f(void) { return 1; }',native_value_flow:flow}}]});
 const portable=await identity('artifacts/native/native-evidence.json');
 await save('cases/native/artifacts/raw',{status:'completed',persisted:true,cleanup:{closed:true},bundleSha256:portable.sha256,saved:{status:'supported',artifact:{sha256:portable.sha256,size_bytes:portable.size_bytes}}});
 const raw=await identity('cases/native/artifacts/raw');
 const receipt={schema_version:1,status:'PASS',scope:'Recorded installation and local expression analysis; no full equivalence claim.',verified_at:'2026-10-19T15:09:27.093Z',host:{platform:process.platform,arch:process.arch},java_home:javaHome,ghidra_install_dir:ghidraHome,archives:[{identity:{path:'.tools/native/archives/large.zip',sha256:'a'.repeat(64),size_bytes:569649598},status:'PASS'}],java:{executable:java,exit_code:0},javac:{executable:javac,exit_code:0},jdk_compiler_present:true,source_files:[target],rea:{package:'rea-agents',version:'6.7.0',provider:{id:'ghidra',version:'12.1.4'},case_directory:path.join(root,'cases/native'),persisted:true,cleanup:{closed:true},evidence_id:'ev_fixture',portable_evidence:portable,raw_acquisition:{relative_path:'artifacts/raw',sha256:raw.sha256,size_bytes:raw.size_bytes}},native_value_flow:{available:true,provenance:'ghidra-high-pcode',operation_count:1,edge_count:0,truncated:false,omitted_operations:0},local_expression:{scope:{kind:'expression',execution_guard:{kind:'unknown'},observation_point:{kind:'local_value'}},target_replay_eligible:false}};
 await save('artifacts/native/deployment.json',receipt);
 return {root,save,identity,receipt,java,headless};
}

describe('native capability status',()=>{
 it('separates present tools, validated recorded local analysis and the historical full gate',async()=>{
  const {root}=await fixture();const status=await loadNativeStatus(root);
  expect(status.current_native_tools.status).toBe('available');
  expect(status.recorded_native_analysis.status).toBe('validated');
  expect(status.recorded_native_analysis.scope).toBe('local_expression_analysis');
  expect(status.recorded_native_analysis.current_execution_verified).toBe(false);
  expect(status.recorded_native_analysis.archives_rechecked).toBe(false);
  expect(status.recorded_native_analysis.referenced_files_verified).toBe(3);
  expect(status.native_ghidra).toBe('RECORDED_LOCAL_ANALYSIS');
  expect(status.last_recorded_native_gate).toBe('BLOCKED');
  expect(status.historical_native_gate.scope).toBe('full_acceptance');
  expect(status.full_binary_equivalence).toBe(false);
 });
 it('keeps recorded evidence separate when a configured executable disappears',async()=>{
  const {root,java}=await fixture();await rm(java);const status=await loadNativeStatus(root);
  expect(status.current_native_tools.status).toBe('incomplete');
  expect(status.current_native_tools.java.present).toBe(false);
  expect(status.recorded_native_analysis.status).toBe('validated');
  expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('does not bind recorded analysis to different presently available tools',async()=>{
  const {root,save}=await fixture();
  for(const name of [process.platform==='win32'?'java.exe':'java',process.platform==='win32'?'javac.exe':'javac'])await save('replacement/bin/'+name,'other tool');
  await save('.local/rea-native.json',{command:path.join(root,'tools/node'),args:[path.join(root,'tools/rea.mjs'),'--mcp'],env:{JAVA_HOME:path.join(root,'replacement'),GHIDRA_INSTALL_DIR:path.join(root,'tools/ghidra')}});
  const status=await loadNativeStatus(root);
  expect(status.current_native_tools.status).toBe('available');
  expect(status.recorded_native_analysis.status).toBe('validated');
  expect(status.recorded_native_analysis.matches_current_tool_paths).toBe(false);
  expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('reports present tools without promoting a missing receipt',async()=>{
  const {root}=await fixture();await rm(path.join(root,'artifacts/native/deployment.json'));const status=await loadNativeStatus(root);
  expect(status.current_native_tools.status).toBe('available');expect(status.recorded_native_analysis.status).toBe('missing');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('does not infer current configuration from an old receipt',async()=>{
  const {root}=await fixture();await rm(path.join(root,'.local/rea-native.json'));const status=await loadNativeStatus(root);
  expect(status.current_native_tools.status).toBe('not_configured');expect(status.recorded_native_analysis.status).toBe('validated');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it.each(['missing','altered'] as const)('rejects %s portable evidence despite a PASS receipt',async mode=>{
  const {root,save}=await fixture();if(mode==='missing')await rm(path.join(root,'artifacts/native/native-evidence.json'));else await save('artifacts/native/native-evidence.json','different bytes');
  const status=await loadNativeStatus(root);expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it.each(['{','{"status":"PASS"}',' '.repeat(256*1024+1)])('bounds and validates the receipt before trusting its status (%#)',async contents=>{
  const {root,save}=await fixture();await save('artifacts/native/deployment.json',contents);const status=await loadNativeStatus(root);
  expect(status.current_native_tools.status).toBe('available');expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('rejects evidence paths escaping the installation root',async()=>{
  const {root,receipt,save}=await fixture();receipt.source_files[0]!.path='../outside.exe';await save('artifacts/native/deployment.json',receipt);
  const status=await loadNativeStatus(root);expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('rejects altered acquisition evidence even if portable evidence still matches',async()=>{
  const {root,save}=await fixture();await save('cases/native/artifacts/raw','different raw acquisition');const status=await loadNativeStatus(root);
  expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('does not upgrade a receipt that claims a full-function scope',async()=>{
  const {root,receipt,save}=await fixture();receipt.local_expression.scope.kind='function';await save('artifacts/native/deployment.json',receipt);
  const status=await loadNativeStatus(root);expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('rejects a hash-matching record without actual pseudocode text',async()=>{
  const {root,receipt,save,identity}=await fixture();const bundle=JSON.parse(await readFile(path.join(root,'artifacts/native/native-evidence.json'),'utf8'));
  bundle.records[0].normalized_result.pseudocode=' \r\n\t';await save('artifacts/native/native-evidence.json',bundle);receipt.rea.portable_evidence=await identity('artifacts/native/native-evidence.json');
  await save('cases/native/artifacts/raw',{status:'completed',persisted:true,cleanup:{closed:true},bundleSha256:receipt.rea.portable_evidence.sha256,saved:{status:'supported',artifact:{sha256:receipt.rea.portable_evidence.sha256,size_bytes:receipt.rea.portable_evidence.size_bytes}}});
  const raw=await identity('cases/native/artifacts/raw');receipt.rea.raw_acquisition={relative_path:'artifacts/raw',sha256:raw.sha256,size_bytes:raw.size_bytes};await save('artifacts/native/deployment.json',receipt);
  const status=await loadNativeStatus(root);expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
 it('rejects ambiguous duplicate evidence identities even when every file hash matches',async()=>{
  const {root,receipt,save,identity}=await fixture();const bundle=JSON.parse(await readFile(path.join(root,'artifacts/native/native-evidence.json'),'utf8'));
  bundle.records.push(structuredClone(bundle.records[0]));await save('artifacts/native/native-evidence.json',bundle);receipt.rea.portable_evidence=await identity('artifacts/native/native-evidence.json');
  await save('cases/native/artifacts/raw',{status:'completed',persisted:true,cleanup:{closed:true},bundleSha256:receipt.rea.portable_evidence.sha256,saved:{status:'supported',artifact:{sha256:receipt.rea.portable_evidence.sha256,size_bytes:receipt.rea.portable_evidence.size_bytes}}});
  const raw=await identity('cases/native/artifacts/raw');receipt.rea.raw_acquisition={relative_path:'artifacts/raw',sha256:raw.sha256,size_bytes:raw.size_bytes};await save('artifacts/native/deployment.json',receipt);
  const status=await loadNativeStatus(root);expect(status.recorded_native_analysis.status).toBe('invalid');expect(status.native_ghidra).toBe('NOT_VERIFIED');
 });
});
