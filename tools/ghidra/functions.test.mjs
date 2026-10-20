import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, writeFile, rm, readdir, link} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {runProcess} from '../../dist/src/process.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const protocol = () => import('./bounded-protocol.mjs');
const tool = () => import('./functions.mjs');
const sampleRequest = () => ({schema_version:1, expected_sha256:'a'.repeat(64),
  entries:[{va:'0x401000',max_bytes:16}],decompile_seconds:2,script_seconds:10});
const errorCode = code => error => error?.code === code;

test('strict JSON refuses duplicate keys including equivalent escaped names', async () => {
  const {parseStrictJson} = await protocol();
  for (const text of ['{"entries":[],"entries":[]}', '{"x":1,"\\u0078":2}'])
    assert.throws(() => parseStrictJson(Buffer.from(text,'utf8')), errorCode('GHIDRA_JSON_INVALID'));
});
test('strict JSON refuses malformed UTF-8 and every nonfinite numeric spelling', async () => {
  const {parseStrictJson} = await protocol();
  for (const data of [Buffer.from([255]),Buffer.from('{"x":NaN}'),Buffer.from('{"x":Infinity}'),Buffer.from('{"x":1e999}')])
    assert.throws(() => parseStrictJson(data), errorCode('GHIDRA_JSON_INVALID'));
});
test('valid request preserves the five-field Java contract', async () => {
  const {validateRequest} = await protocol();
  assert.deepEqual(validateRequest(sampleRequest()), sampleRequest());
});
test('request rejects unknown or missing fields at either nesting level', async () => {
  const {validateRequest} = await protocol();
  for (const change of [value => {value.pid=1;}, value => {delete value.script_seconds;},
      value => {value.entries[0].follow=true;},value => {delete value.entries[0].max_bytes;}]) {
    const value = sampleRequest(); change(value);
    assert.throws(() => validateRequest(value), errorCode('GHIDRA_REQUEST_INVALID'));
  }
});
test('request rejects repeated numeric addresses despite case or zero padding', async () => {
  const {validateRequest} = await protocol();
  const value=sampleRequest(); value.entries=[{va:'0x00ABCDEF',max_bytes:1},{va:'0xabcdef',max_bytes:1}];
  assert.throws(() => validateRequest(value), errorCode('GHIDRA_REQUEST_INVALID'));
});
test('request enforces entry, VA32, byte, decompiler and script budgets', async () => {
  const {validateRequest} = await protocol();
  for (const patch of [{entries:[]},{entries:Array.from({length:6},(_,i)=>({va:'0x'+(i+1).toString(16),max_bytes:1}))},
      {entries:[{va:'0x100000000',max_bytes:1}]},{entries:[{va:'0xffffffff',max_bytes:2}]},
      {entries:[{va:'0x401000',max_bytes:0}]},{entries:[{va:'0x401000',max_bytes:2049}]},
      {decompile_seconds:0},{decompile_seconds:6},{script_seconds:0},{script_seconds:46},
      {schema_version:true},{expected_sha256:'A'.repeat(64)}])
    assert.throws(() => validateRequest({...sampleRequest(),...patch}), errorCode('GHIDRA_REQUEST_INVALID'));
});

function peFixture() {
  const data=Buffer.alloc(1024); data.write('MZ',0,'ascii'); data.writeUInt32LE(0x80,0x3c);
  data.write('PE\0\0',0x80,'ascii'); data.writeUInt16LE(0x14c,0x84); data.writeUInt16LE(1,0x86);
  data.writeUInt16LE(0xe0,0x94); data.writeUInt16LE(0x102,0x96);
  const optional=0x98; data.writeUInt16LE(0x10b,optional); data.writeUInt32LE(0x1000,optional+16);
  data.writeUInt32LE(0x400000,optional+28); data.writeUInt32LE(0x1000,optional+32);
  data.writeUInt32LE(0x200,optional+36); data.writeUInt32LE(0x2000,optional+56); data.writeUInt32LE(0x200,optional+60);
  const section=0x178;data.write('.text',section,'ascii');data.writeUInt32LE(0x1000,section+8);
  data.writeUInt32LE(0x1000,section+12);data.writeUInt32LE(0x200,section+16);data.writeUInt32LE(0x200,section+20);
  data.writeUInt32LE(0x60000020,section+36);data[0x200]=0x90;data[0x201]=0xc3;
  return data;
}

function artifacts(request,input,mode='success') {
  const row={entry_va:'0x00401000',guarded_bytes_sha256:sha(input.subarray(0x200,0x210)),
    entry_source:'explicit candidate address, not discovered identity',
    allowed_ranges:[{start:'0x00401000',end_inclusive:'0x0040100f'}],max_bytes:16,
    follow_flow:'explicit finite instruction worklist; call targets and other candidate entries excluded',
    incremental_code_analysis:false,coverage:'partial bounded static observation of an analysis dump',
    body_ranges:[{start:'0x00401000',end_inclusive:'0x00401001'}],body_bytes:2,instruction_count:2,raw_pcode_count:1,
    listing:[{va:'0x00401000',bytes:'90',text:'NOP',flow_type:'FALL_THROUGH',fallthrough:'0x00401001'},
      {va:'0x00401001',bytes:'c3',text:'RET',flow_type:'TERMINATOR'}],
    instruction_edges:[{from:'0x00401000',to:'0x00401001',kind:'fallthrough',outside_guard:false,target_memory_block:'.text'}],
    calls:[],unknown_or_guard_exits:[],guard:'Only listed reachable instruction bytes are in scope; ABI and complete boundaries are unverified.',
    decompilation:{timeout_seconds:2,completed:true,timed_out:false,cancelled:false,diagnostic:'',signature:'void candidate(void);',
      high_pcode_count:1,outside_body_pcs:[],scope_accepted:true,frontend_address_restriction:'Every high-pcode PC checked against body.',c_file:'00401000.c'},
    status:'observed',duration_ms:1};
  const raw=[{pc:'0x00401001',ordinal:0,op:'RETURN',output:null,inputs:[]}];
  const high=[{pc:'0x00401001',ordinal:0,op:'RETURN',output:null,inputs:[]}];
  const files={'00401000.c':'void candidate(void) { return; }\n'};
  if(mode==='partial') {row.status='decompile_incomplete';row.decompilation.completed=false;delete row.decompilation.c_file;delete files['00401000.c'];}
  if(mode==='rejected'||mode==='escape') {
    high[0].pc='0x00401010';
    if(mode==='rejected') {row.status='scope_rejected';row.error_code='DECOMPILER_SCOPE_ESCAPE';row.decompilation.scope_accepted=false;
      row.decompilation.outside_body_pcs=['0x00401010'];row.decompilation.unaccepted_c_file='00401000.scope-rejected.c';
      delete row.decompilation.c_file;files['00401000.scope-rejected.c']=files['00401000.c'];delete files['00401000.c'];}
  }
  if(mode==='listing-bytes') row.listing[0].bytes='91';
  if(mode==='raw-escape') raw[0].pc='0x00401010';
  if(mode==='bad-body') row.body_bytes=3;
  if(mode==='bad-request') row.max_bytes=17;
  if(mode==='traversal') row.decompilation.c_file='../outside.c';
  const summary={schema_version:1,provider:'ghidra-public-bounded-static',ghidra_version:'synthetic-not-ghidra',
    input_sha256:request.expected_sha256,language:'x86:LE:32:default',compiler_spec:'windows',image_base:'0x00400000',
    auto_analysis:false,script_seconds:request.script_seconds,target_executed:false,request,functions:[row],
    status:['partial','rejected'].includes(mode)?'partial':'completed',elapsed_script_ms:1};
  if(mode==='wrong-input') summary.input_sha256='0'.repeat(64);
  if(mode==='auto-analysis') summary.auto_analysis=true;
  files['00401000.json']=JSON.stringify(row);files['00401000.pcode.json']=JSON.stringify(raw);
  files['00401000.high-pcode.json']=JSON.stringify(high);files['summary.json']=JSON.stringify(summary);
  return files;
}

const childSource=`import {readFile,writeFile} from 'node:fs/promises';import path from 'node:path';
const [out,bundle,mode]=process.argv.slice(2);const files=JSON.parse(await readFile(bundle,'utf8'));
for(const [name,text] of Object.entries(files))await writeFile(path.join(out,name),text,{encoding:'utf8',flag:'wx'});
process.stdout.write('SYNTHETIC_ONLY_NO_GHIDRA_OR_PE_EXECUTION\\n');process.stderr.write('fixture diagnostic\\n');
if(mode==='receipt-collision')await writeFile(path.join(out,'..','receipt.json'),'owned collision sentinel',{encoding:'utf8',flag:'wx'});
if(mode==='hang')setTimeout(()=>{},30000);else process.exitCode=['exit2','receipt-collision'].includes(mode)?2:0;`;

async function fixture(t,mode='success') {
  const root=await mkdtemp(path.join(os.tmpdir(),'wirefit-ghidra-test-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const input=peFixture(),request={...sampleRequest(),expected_sha256:sha(input)};
  const javaHome=path.join(root,"jdk's-home"),ghidra=path.join(root,'ghidra'),bin=path.join(javaHome,'bin');
  await mkdir(bin,{recursive:true});await mkdir(path.join(ghidra,'support'),{recursive:true});
  await writeFile(path.join(bin,process.platform==='win32'?'java.exe':'java'),'synthetic Java identity',{encoding:'utf8',flag:'wx'});
  await writeFile(path.join(ghidra,'support',process.platform==='win32'?'analyzeHeadless.bat':'analyzeHeadless'),'synthetic headless identity',{encoding:'utf8',flag:'wx'});
  const source=path.join(root,'source.exe'),requestPath=path.join(root,'request.json'),nativePath=path.join(root,'native.json');
  await writeFile(source,input,{flag:'wx'});await writeFile(requestPath,JSON.stringify(request),{encoding:'utf8',flag:'wx'});
  await writeFile(nativePath,JSON.stringify({java_home:javaHome,ghidra_install_dir:ghidra,previous_user_environment:{SECRET:'must-not-be-copied'}}),{encoding:'utf8',flag:'wx'});
  const bundle=path.join(root,'bundle.json'),child=path.join(root,'child.mjs');
  await writeFile(bundle,JSON.stringify(artifacts(request,input,mode)),{encoding:'utf8',flag:'wx'});
  await writeFile(child,childSource,{encoding:'utf8',flag:'wx'});
  let starts=0;
  const options={input:source,request:requestPath,out:path.join(root,'new-output'),native:nativePath};
  const run=async (_command,_args,processOptions)=>{
    starts++;assert.equal(processOptions.timeout_ms,60000);
    assert.equal(processOptions.env.JAVA_HOME,javaHome);
    return runProcess(process.execPath,[child,path.join(options.out,'analysis'),bundle,mode],
      {...processOptions,...(mode==='hang'?{timeout_ms:100}:{})});
  };
  return {root,input,request,source,requestPath,nativePath,bundle,options,run,get starts(){return starts;}};
}

test('existing output is rejected before spawning or writing any evidence', async t => {
  const f=await fixture(t);await mkdir(f.options.out);await writeFile(path.join(f.options.out,'old.txt'),'old','utf8');
  const {runBoundedFunctions}=await tool();
  await assert.rejects(runBoundedFunctions(f.options,{run:f.run}),errorCode('GHIDRA_OUTPUT_INVALID'));
  assert.equal(f.starts,0);assert.deepEqual(await readdir(f.options.out),['old.txt']);
});
test('source SHA mismatch leaves output absent and starts no child', async t => {
  const f=await fixture(t);await writeFile(f.requestPath,JSON.stringify({...f.request,expected_sha256:'0'.repeat(64)}),'utf8');
  const {runBoundedFunctions}=await tool();
  await assert.rejects(runBoundedFunctions(f.options,{run:f.run}),errorCode('GHIDRA_INPUT_INVALID'));
  assert.equal(f.starts,0);await assert.rejects(readFile(path.join(f.options.out,'receipt.json')), {code:'ENOENT'});
});
test('hardlinked source input is rejected without creating output', async t => {
  const f=await fixture(t);await link(f.source,path.join(f.root,'source-link.exe'));
  const {runBoundedFunctions}=await tool();
  await assert.rejects(runBoundedFunctions(f.options,{run:f.run}),errorCode('GHIDRA_PATH_INVALID'));
  assert.equal(f.starts,0);await assert.rejects(readdir(f.options.out),{code:'ENOENT'});
});
test('real Node fixture success retains actual PID, stable copies and sanitized native selection', async t => {
  const f=await fixture(t);const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'completed');assert.ok(receipt.execution.pid>0);assert.equal(receipt.execution.code,0);
  assert.equal(receipt.execution_backend,'injected_run_port');assert.equal(receipt.target_executed,false);
  assert.equal(receipt.validation.source_unchanged,true);assert.equal(receipt.validation.code_unchanged,true);
  assert.ok(receipt.args.includes('-noanalysis'));assert.ok(receipt.args.includes('-readOnly'));
  assert.equal(receipt.args[receipt.args.indexOf('-max-cpu')+1],'1');
  assert.equal(receipt.args[receipt.args.indexOf('-postScript')+1],'WirefitBoundedFunctions.java');
  assert.equal(receipt.functions[0].scope_accepted,true);assert.equal(receipt.functions[0].body_bytes,2);
  assert.deepEqual(await readFile(path.join(f.options.out,'inputs','analysis-input.exe')),f.input);
  assert.match(await readFile(path.join(f.options.out,'stdout.txt'),'utf8'),/SYNTHETIC_ONLY/);
  assert.equal(JSON.stringify(receipt).includes('must-not-be-copied'),false);
});
test('valid incomplete decompilation remains partial despite child exit zero', async t => {
  const f=await fixture(t,'partial');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'partial');assert.equal(receipt.execution.code,0);assert.equal(receipt.functions[0].status,'decompile_incomplete');
  assert.equal(receipt.functions[0].accepted_c_file,null);
});
test('real scope rejection preserves diagnostic C without accepting it', async t => {
  const f=await fixture(t,'rejected');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'partial');assert.equal(receipt.functions[0].status,'scope_rejected');
  assert.equal(receipt.functions[0].accepted_c_file,null);assert.equal(receipt.functions[0].outside_body_pcs.length,1);
  assert.match(await readFile(path.join(f.options.out,'analysis','00401000.scope-rejected.c'),'utf8'),/candidate/);
});
test('claimed observed scope is refused when actual high-pcode PC escapes', async t => {
  const f=await fixture(t,'escape');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_SUMMARY_INVALID');
});
test('raw p-code PC must belong to independently recomputed listing body', async t => {
  const f=await fixture(t,'raw-escape');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_SUMMARY_INVALID');
});
test('self-consistent listing text cannot replace staged PE instruction bytes', async t => {
  const f=await fixture(t,'listing-bytes');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_SUMMARY_INVALID');
});
test('body accounting mismatch cannot be hidden behind completed flags', async t => {
  const f=await fixture(t,'bad-body');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_SUMMARY_INVALID');
});
test('summary input identity, analysis mode and request guards are revalidated', async t => {
  for(const mode of ['wrong-input','auto-analysis','bad-request']) {
    const f=await fixture(t,mode);const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
    assert.equal(receipt.status,'failed',mode);assert.equal(receipt.error.code,'GHIDRA_SUMMARY_INVALID',mode);
  }
});
test('artifact traversal is refused before an external C path can be opened', async t => {
  const f=await fixture(t,'traversal');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_SUMMARY_INVALID');
});
test('nonzero child remains the first error even if its summary is invalid', async t => {
  const f=await fixture(t,'exit2');const files=JSON.parse(await readFile(f.bundle,'utf8'));files['summary.json']='bad JSON';
  await writeFile(f.bundle,JSON.stringify(files),'utf8');const {runBoundedFunctions}=await tool();
  const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_EXIT_FAILED');
  assert.equal(receipt.execution.code,2);assert.match(receipt.execution.stderr,/fixture diagnostic/);
  assert.ok(receipt.finalization_errors.some(error=>error.code==='GHIDRA_JSON_INVALID'));
});
test('timeout preserves actual close evidence and cannot accept a prewritten success summary', async t => {
  const f=await fixture(t,'hang');const {runBoundedFunctions}=await tool();const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'TIMEOUT');
  assert.ok(receipt.execution.pid>0);assert.equal(receipt.execution.cleanup,'closed');
  assert.match(await readFile(path.join(f.options.out,'stdout.txt'),'utf8'),/SYNTHETIC_ONLY/);
});
test('late source mutation downgrades success while retaining observed output', async t => {
  const f=await fixture(t);const {runBoundedFunctions}=await tool();const run=async(...args)=>{
    const result=await f.run(...args);const changed=Buffer.from(f.input);changed[900]=1;await writeFile(f.source,changed);return result;};
  const receipt=await runBoundedFunctions(f.options,{run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_INPUT_CHANGED');
  assert.equal(receipt.validation.source_unchanged,false);assert.equal(receipt.functions[0].body_bytes,2);
});
test('Windows launcher quotes apostrophes and refuses batch expansion metacharacters', async () => {
  const {buildLauncher}=await tool();
  const options={platform:'win32',java_home:"C:\\jdk's-home",headless:'C:\\ghidra\\support\\analyzeHeadless.bat',args:['C:\\owned\\project','name','-noanalysis','-readOnly']};
  const text=buildLauncher(options);assert.match(text,/jdk''s-home/);assert.match(text,/-noanalysis/);assert.match(text,/-readOnly/);
  for(const bad of ['%TEMP%','a&b','a!b','a^b','a(b)'])
    assert.throws(()=>buildLauncher({...options,args:[bad]}),errorCode('GHIDRA_PATH_INVALID'));
});
test('public CLI refuses extra or repeated flags without starting Ghidra or creating output', async t => {
  const f=await fixture(t);
  const args=['--input',f.source,'--request',f.requestPath,'--out',f.options.out,'--native',f.nativePath];
  for(const extra of [['--script','arbitrary.java'],['--input',f.source]]) {
    const execution=await runProcess(process.execPath,[path.join(here,'functions.mjs'),...args,...extra],
      {cwd:here,timeout_ms:5000});
    assert.equal(execution.code,1);assert.equal(JSON.parse(execution.stdout).error.code,'GHIDRA_ARGUMENTS_INVALID');
    await assert.rejects(readdir(f.options.out),{code:'ENOENT'});
  }
});
test('virtual-only or unmapped selected PE guards fail before any child or output', async t => {
  const f=await fixture(t);const {runBoundedFunctions}=await tool();
  for(const va of ['0x401200','0x402000']) {
    await writeFile(f.requestPath,JSON.stringify({...f.request,entries:[{va,max_bytes:16}]}),'utf8');
    await assert.rejects(runBoundedFunctions(f.options,{run:f.run}),errorCode('GHIDRA_INPUT_INVALID'));
    assert.equal(f.starts,0);await assert.rejects(readdir(f.options.out),{code:'ENOENT'});
  }
});
test('actual process startup failure preserves its execution record and original error', async t => {
  const f=await fixture(t);const {runBoundedFunctions}=await tool();
  const run=(_command,_args,options)=>runProcess(path.join(f.root,'no-such-owned-child.exe'),[],options);
  const receipt=await runBoundedFunctions(f.options,{run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'PROCESS_START_FAILED');
  assert.equal(receipt.execution.pid,0);assert.equal(receipt.execution.cleanup,'closed');
  assert.equal(await readFile(path.join(f.options.out,'stdout.txt'),'utf8'),'');
});
test('late receipt collision preserves first child failure and actual execution without overwriting', async t => {
  const f=await fixture(t,'receipt-collision');const {runBoundedFunctions,receiptSummary}=await tool();
  const receipt=await runBoundedFunctions(f.options,{run:f.run});
  assert.equal(receipt.status,'failed');assert.equal(receipt.error.code,'GHIDRA_EXIT_FAILED');
  assert.equal(receipt.receipt_saved,false);assert.equal(receipt.log_error.code,'EEXIST');
  assert.ok(receipt.execution.pid>0);assert.equal(receipt.execution.code,2);
  assert.match(receipt.execution.stderr,/fixture diagnostic/);
  assert.equal(await readFile(path.join(f.options.out,'receipt.json'),'utf8'),'owned collision sentinel');
  const printed=receiptSummary(receipt);
  assert.equal(printed.error.code,'GHIDRA_EXIT_FAILED');assert.equal(printed.log_error.code,'EEXIST');
  assert.equal(printed.execution.pid,receipt.execution.pid);assert.equal(printed.execution.code,2);
  assert.equal(printed.stdio.stdout.path,path.join(f.options.out,'stdout.txt'));assert.equal(printed.stdio.stdout.saved,true);
});
