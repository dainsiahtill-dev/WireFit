import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {runProcess} from '../../dist/src/process.js';
import {assertNewOutput,ordinaryPath,readStable,writeNew,generatedFiles,identity,
  requireThat,sha256,safePath} from './bounded-files.mjs';
import {parseStrictJson,validateRequest,selectedPeBytes,validateSummary} from './bounded-protocol.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const ROOT=path.resolve(HERE,'../..');
const JAVA_NAME='WirefitBoundedFunctions.java';
const JAVA_SHA='acba15f349e21719ac46a26ddc42db8fd44ee079f60cea33112349400018c0c3';
const LIMIT=128*1024*1024;
const errorRecord=error=>({code:typeof error?.code==='string'?error.code:'GHIDRA_OPERATION_FAILED',
  message:String(error?.message??error).replaceAll('\0','?').slice(0,8192)});
const json=value=>JSON.stringify(value,null,2)+'\n';
const quotePs=value=>"'"+value.replaceAll("'","''")+"'";
const quoteSh=value=>"'"+value.replaceAll("'","'\\''")+"'";

export function buildLauncher({platform=process.platform,java_home,headless,args}) {
  requireThat(typeof java_home==='string'&&typeof headless==='string'&&Array.isArray(args)
    &&args.every(value=>typeof value==='string'&&!/[\x00-\x1f]/.test(value)),
    'GHIDRA_PATH_INVALID','Launcher requires explicit bounded arguments');
  if(platform==='win32') {
    requireThat([java_home,headless,...args].every(value=>!/["%&!^()\x00-\x1f]/.test(value)),
      'GHIDRA_PATH_INVALID','Batch expansion metacharacters are not accepted');
    return ['\ufeff$ErrorActionPreference = \'Stop\'',
      '[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)',
      '$OutputEncoding = [System.Text.UTF8Encoding]::new($false)',
      '$env:JAVA_HOME = '+quotePs(java_home),
      '$env:PATH = '+quotePs(path.win32.join(java_home,'bin')+';')+' + $env:PATH',
      ...['GHIDRA_HEADLESS_JAVA_OPTIONS','GHIDRA_JAVA_OPTIONS','JDK_JAVA_OPTIONS','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS']
        .map(name=>'$env:'+name+" = ''"),
      '& '+quotePs(headless)+' '+args.map(quotePs).join(' '),
      'exit $LASTEXITCODE',''].join('\n');
  }
  return ['#!/bin/sh','set -eu','export JAVA_HOME='+quoteSh(java_home),
    'export PATH='+quoteSh(path.join(java_home,'bin')+':')+'"$PATH"',
    ...['GHIDRA_HEADLESS_JAVA_OPTIONS','GHIDRA_JAVA_OPTIONS','JDK_JAVA_OPTIONS','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS']
      .map(name=>'export '+name+"=''"),
    'exec '+quoteSh(headless)+' '+args.map(quoteSh).join(' '),''].join('\n');
}

async function prepare(options) {
  requireThat(options&&typeof options==='object'&&Object.keys(options).sort().join(',')==='input,native,out,request',
    'GHIDRA_ARGUMENTS_INVALID','Exactly input, request, out and native paths are required');
  // Output collision and unsafe parent checks precede input snapshots or mutation.
  const out=await assertNewOutput(options.out);
  const source=await readStable(options.input,LIMIT),requestInput=await readStable(options.request,32768);
  const request=validateRequest(parseStrictJson(requestInput.bytes,32768));
  requireThat(source.sha256===request.expected_sha256,'GHIDRA_INPUT_INVALID','Input SHA differs from the explicit request');
  const pe=selectedPeBytes(source.bytes,request),nativeInput=await readStable(options.native,1024*1024);
  const native=parseStrictJson(nativeInput.bytes,1024*1024);
  requireThat(native&&typeof native==='object'&&!Array.isArray(native)
    &&typeof native.java_home==='string'&&typeof native.ghidra_install_dir==='string',
    'GHIDRA_NATIVE_INVALID','Native installation must supply java_home and ghidra_install_dir');
  const javaHome=await ordinaryPath(native.java_home,'directory');
  const ghidra=await ordinaryPath(native.ghidra_install_dir,'directory');
  const runtime=[await readStable(path.join(javaHome,'bin',process.platform==='win32'?'java.exe':'java'),64*1024*1024),
    await readStable(path.join(ghidra,'support',process.platform==='win32'?'analyzeHeadless.bat':'analyzeHeadless'),1024*1024)];
  const code=[];
  for(const file of [path.join(HERE,JAVA_NAME),fileURLToPath(import.meta.url),path.join(HERE,'bounded-files.mjs'),
      path.join(HERE,'bounded-protocol.mjs'),path.join(ROOT,'dist/src/process.js'),path.join(ROOT,'dist/src/shared.js'),
      path.join(ROOT,'dist/src/pe.js')])code.push(await readStable(file,1024*1024));
  requireThat(code[0].sha256===JAVA_SHA&&code[0].size_bytes===18329,
    'GHIDRA_CODE_INVALID','Fixed bounded Java script differs from the reviewed identity');
  const inputs=path.join(out,'inputs'),analysis=path.join(out,'analysis');
  const args=[path.join(out,'project'),'wirefit-bounded','-import',path.join(inputs,'analysis-input.exe'),
    '-noanalysis','-readOnly','-scriptPath',inputs,'-postScript',JAVA_NAME,path.join(inputs,'request.json'),analysis,
    '-max-cpu','1','-log',path.join(out,'ghidra.log'),'-scriptlog',path.join(out,'script.log')];
  const launcher=buildLauncher({java_home:javaHome,headless:runtime[1].path,args});
  return {out,source,requestInput,request,nativeInput,pe,javaHome,ghidra,runtime,code,inputs,analysis,args,launcher};
}

/** The optional run port is programmatic test injection; CLI always uses runProcess. */
export async function runBoundedFunctions(options,ports={}) {
  const prepared=await prepare(options);
  const {out,source,requestInput,request,nativeInput,pe,javaHome,ghidra,runtime,code,inputs,analysis,args,launcher}=prepared;
  try { await mkdir(out); } catch(error) {
    const wrapped=new Error('Could not exclusively create output: '+error.message);wrapped.code='GHIDRA_OUTPUT_INVALID';throw wrapped;
  }
  const receipt={schema_version:1,kind:'bounded_ghidra_functions',status:'failed',started_at:new Date().toISOString(),
    source:identity(source),request,request_input:identity(requestInput),out,
    code:code.map(identity),java_script:identity(code[0]),
    native_installation:{configuration:identity(nativeInput),java_home:javaHome,ghidra_install_dir:ghidra,
      selected_files:runtime.map(identity),sdk_or_jar_closure_verified:false},
    execution_backend:ports.run?'injected_run_port':'ghidra_headless',
    platform:{name:process.platform,headless_on_this_platform_verified:false},
    hard_process_budget_ms:60000,max_cpu:1,auto_analysis:false,target_executed:false,
    read_only_project:true,args,execution:null,functions:[],error:null,finalization_errors:[],
    receipt_saved:false,log_error:null,
    stdio:{stdout:{path:path.join(out,'stdout.txt'),saved:false},stderr:{path:path.join(out,'stderr.txt'),saved:false}},
    validation:{source_unchanged:false,code_unchanged:false,request_unchanged:false,
      native_configuration_unchanged:false,selected_runtime_files_unchanged:false,staged_copies_unchanged:false},
    scope:'bounded static observations only; no function ABI, complete-function, dependency or runnable-image proof',
    runnable_verified:false};
  const fail=error=>{
    const record=errorRecord(error);
    if(receipt.error===null)receipt.error=record;else receipt.finalization_errors.push(record);
    receipt.status='failed';
  };
  const staged=[],observations=new Map();
  const observe=async(name,limit=4*1024*1024)=>{
    requireThat(/^[A-Za-z0-9_.-]{1,120}$/.test(name),'GHIDRA_SUMMARY_INVALID','Invalid analysis artifact basename');
    const snapshot=await readStable(path.join(analysis,name),limit),previous=observations.get(name);
    requireThat(!previous||(previous.sha256===snapshot.sha256&&previous.size_bytes===snapshot.size_bytes),
      'GHIDRA_FILE_CHANGED','Analysis artifact changed between observations');observations.set(name,snapshot);return snapshot.bytes;
  };
  try {
    await mkdir(inputs);await mkdir(analysis);await mkdir(path.join(out,'project'));
    staged.push(await writeNew(path.join(inputs,'analysis-input.exe'),source.bytes));
    staged.push(await writeNew(path.join(inputs,'request-original.json'),requestInput.bytes));
    staged.push(await writeNew(path.join(inputs,'request.json'),json(request)));
    staged.push(await writeNew(path.join(inputs,JAVA_NAME),code[0].bytes));
    const launcherPath=path.join(out,process.platform==='win32'?'launch.ps1':'launch.sh');
    staged.push(await writeNew(launcherPath,launcher));receipt.launcher={...identity(staged.at(-1)),
      used:process.platform==='win32',encoding:'UTF-8',bom:process.platform==='win32'};
    const env={...process.env,JAVA_HOME:javaHome,PATH:path.join(javaHome,'bin')+path.delimiter+(process.env.PATH??''),
      GHIDRA_HEADLESS_JAVA_OPTIONS:'',GHIDRA_JAVA_OPTIONS:'',JDK_JAVA_OPTIONS:'',JAVA_TOOL_OPTIONS:'',_JAVA_OPTIONS:'',
      NODE_OPTIONS:'',NODE_PATH:''};
    const command=process.platform==='win32'?path.join(process.env.SystemRoot??'C:\\Windows','System32/WindowsPowerShell/v1.0/powershell.exe'):runtime[1].path;
    const childArgs=process.platform==='win32'?['-NoProfile','-NonInteractive','-File',launcherPath]:args;
    receipt.command={file:command,args:childArgs};
    try {
      receipt.execution=await (ports.run??runProcess)(command,childArgs,
        {cwd:out,env,timeout_ms:60000,max_stdout_bytes:4*1024*1024,max_stderr_bytes:1024*1024,signal:ports.signal});
      if(receipt.execution.code!==0||receipt.execution.signal!==null) {
        const error=new Error('Headless child did not exit successfully');error.code='GHIDRA_EXIT_FAILED';fail(error);
      }
    } catch(error) { receipt.execution=error.details??null;fail(error); }
    if(receipt.execution) {
      receipt.stdio.stdout={...identity(await writeNew(path.join(out,'stdout.txt'),receipt.execution.stdout??'')),saved:true};
      receipt.stdio.stderr={...identity(await writeNew(path.join(out,'stderr.txt'),receipt.execution.stderr??'')),saved:true};
    }
    try {
      const summaryBytes=await observe('summary.json'),summary=parseStrictJson(summaryBytes);
      const accepted=await validateSummary(summary,request,pe,observe);
      receipt.summary=identity(observations.get('summary.json'));receipt.functions=accepted.functions;
      receipt.ghidra_version=accepted.ghidra_version;
      if(receipt.error===null)receipt.status=accepted.status;
      receipt.platform.headless_on_this_platform_verified=!ports.run;
    } catch(error) { fail(error); }
  } catch(error) { fail(error); }
  const checkSnapshots=async(snapshots,key,codeName)=>{
    let confirmed=true;
    for(const original of snapshots) {
      try {
        const current=await readStable(original.path,Math.max(1,original.size_bytes));
        requireThat(current.sha256===original.sha256&&current.size_bytes===original.size_bytes,codeName,'Input/code bytes changed after analysis');
      } catch(error) {
        confirmed=false;
        const changed=new Error('Final identity check failed for '+original.path+': '+error.message);changed.code=codeName;fail(changed);
      }
    }
    receipt.validation[key]=confirmed;
  };
  await checkSnapshots([source],'source_unchanged','GHIDRA_INPUT_CHANGED');
  await checkSnapshots([requestInput],'request_unchanged','GHIDRA_INPUT_CHANGED');
  await checkSnapshots(code,'code_unchanged','GHIDRA_CODE_CHANGED');
  await checkSnapshots([nativeInput],'native_configuration_unchanged','GHIDRA_INPUT_CHANGED');
  await checkSnapshots(runtime,'selected_runtime_files_unchanged','GHIDRA_CODE_CHANGED');
  await checkSnapshots(staged,'staged_copies_unchanged','GHIDRA_INPUT_CHANGED');
  try {
    receipt.analysis_artifacts=await generatedFiles(analysis);
    for(const original of observations.values()) {
      const actual=receipt.analysis_artifacts.find(row=>row.path===original.path);
      requireThat(actual&&actual.sha256===original.sha256&&actual.size_bytes===original.size_bytes,
        'GHIDRA_FILE_CHANGED','Validated analysis artifact changed before receipt');
    }
  } catch(error) { fail(error); }
  receipt.finished_at=new Date().toISOString();
  try {
    receipt.receipt_saved=true;
    await writeNew(path.join(out,'receipt.json'),json(receipt));
  } catch(error) {
    receipt.receipt_saved=false;receipt.log_error=errorRecord(error);fail(error);
  }
  return receipt;
}

export function receiptSummary(receipt) {
  const output={status:receipt.status,out:receipt.out,receipt:path.join(receipt.out,'receipt.json'),
    receipt_saved:receipt.receipt_saved,error:receipt.error,
    functions:receipt.functions.map(row=>({entry_va:row.entry_va,status:row.status,scope_accepted:row.scope_accepted})),
    target_executed:false,runnable_verified:false};
  if(!receipt.receipt_saved) {
    output.log_error=receipt.log_error;output.finalization_errors=receipt.finalization_errors;
    output.execution=receipt.execution;output.stdio=receipt.stdio;
  }
  return output;
}

export function parseArguments(argv) {
  const result={};
  for(let index=0;index<argv.length;index+=2) {
    const name=argv[index];
    requireThat(['--input','--request','--out','--native'].includes(name)&&typeof argv[index+1]==='string'
      &&!argv[index+1].startsWith('--')&&!Object.hasOwn(result,name.slice(2)),
      'GHIDRA_ARGUMENTS_INVALID','Expected each of --input, --request, --out and --native exactly once');
    result[name.slice(2)]=argv[index+1];
  }
  requireThat(Object.keys(result).length===4,'GHIDRA_ARGUMENTS_INVALID','Four explicit paths are required');return result;
}

export async function main(argv=process.argv.slice(2)) {
  const controller=new AbortController(),cancel=()=>controller.abort();
  process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
  try {
    const receipt=await runBoundedFunctions(parseArguments(argv),{signal:controller.signal});
    console.log(JSON.stringify(receiptSummary(receipt)));
    return receipt.error?.code==='CANCELLED'?130:receipt.status==='completed'?0:1;
  } catch(error) { console.log(JSON.stringify({status:'failed',error:errorRecord(error),target_executed:false}));return 1; }
  finally { process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel); }
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))process.exitCode=await main();
