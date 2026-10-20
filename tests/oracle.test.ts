import {describe,it,expect} from 'vitest';
import {mkdtemp,writeFile,readFile,rm,mkdir,symlink,unlink} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {bindOracle,callOracle} from '../src/oracle.js';
import {sha256} from '../src/shared.js';
async function fixture(script:string){
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-oracle-'));
 const target=path.join(dir,'target.cjs');
 await writeFile(target,script,'utf8');
 const manifest={schema_version:1,oracle_id:'test_oracle',kind:'process_jsonl',source_kind:'reference_fixture',argv:[process.execPath,target],cwd:'.',signature:{inputs:[{id:'x',type:{kind:'bv',width:64}}],outputs:[{id:'result',type:{kind:'bv',width:64}}]},domain:{constraints:[]},target_files:[{path:'target.cjs',sha256:sha256(await readFile(target)),role:'target'}],protocol_version:1,reset_strategy:'fresh_process',request_timeout_ms:2000,batch_timeout_ms:10000,max_stdout_line_bytes:1048576,max_stderr_bytes:1048576,allowed_env_keys:[],notes:'source-owned test target'};
 const file=path.join(dir,'oracle.json');await writeFile(file,JSON.stringify(manifest),'utf8');
 return {dir,target,file};
}
const sample={sample_id:'sample1',split:'train',inputs:{x:{kind:'bv',width:64,bits:'0x0020000000000001'}}};
describe('explicit fresh-process Oracle',()=>{
 it('keeps exact typed observations and target identity',async()=>{
  const f=await fixture('let text="";process.stdin.setEncoding("utf8");process.stdin.on("data",d=>text+=d);process.stdin.on("end",()=>{const q=JSON.parse(text);console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:"ok",outputs:{result:q.inputs.x}}));});');
  try{
   const binding=await bindOracle(f.file);
   const result=await callOracle(binding,sample);
   expect(result.observation.status).toBe('ok');
   expect(result.observation.outputs.result.bits).toBe('0x0020000000000001');
   expect(result.observation.record_kind).toBe('observed');
   expect(result.actual_calls).toBe(1);
  }finally{await rm(f.dir,{recursive:true,force:true});}
 });
 it('keeps protocol failure in observation denominator',async()=>{
  const f=await fixture('console.log("this is a log, not protocol");');
  try{const result=await callOracle(await bindOracle(f.file),sample);expect(result.observation.status).toBe('protocol_error');expect(result.actual_calls).toBe(1);expect(result.observation.outputs).toEqual({});}
  finally{await rm(f.dir,{recursive:true,force:true});}
 });
 it('invalidates changed target before it is executed',async()=>{
  const f=await fixture('process.exit(0)');
  try{const binding=await bindOracle(f.file);await writeFile(f.target,'process.exit(77)','utf8');const result=await callOracle(binding,sample);expect(result.observation.error.code).toBe('TARGET_CHANGED');expect(result.actual_calls).toBe(0);}
  finally{await rm(f.dir,{recursive:true,force:true});}
 });
});

it('retains partial stdout and stderr on a real timed-out Oracle call',async()=>{
 const f=await fixture('process.stdout.write("partial target output");process.stderr.write("diagnostic before timeout");setInterval(()=>{},1000);');
 try{const result=await callOracle(await bindOracle(f.file),sample,{timeout_ms:150});expect(result.observation.status).toBe('timeout');expect(result.actual_calls).toBe(1);expect(result.execution?.stdout).toBe('partial target output');expect(result.execution?.stderr).toBe('diagnostic before timeout');expect(result.execution?.pid).toBeGreaterThan(0);}
 finally{await rm(f.dir,{recursive:true,force:true});}
});
it('counts an out-of-domain call as a failed observation without launching the target',async()=>{
 const f=await fixture('process.exit(99)');
 try{const manifest=JSON.parse(await readFile(f.file,'utf8'));manifest.domain.constraints=[{input:'x',op:'eq',value:{kind:'bv',width:64,bits:'0x0000000000000000'}}];await writeFile(f.file,JSON.stringify(manifest),'utf8');const result=await callOracle(await bindOracle(f.file),sample);expect(result.observation.status).toBe('out_of_domain');expect(result.actual_calls).toBe(0);expect(result.execution).toBe(null);}
 finally{await rm(f.dir,{recursive:true,force:true});}
});


it('invalidates a retargeted argument path before launching an undeclared file',async()=>{
 const f=await fixture('process.exit(0)');
 try{const original=path.join(f.dir,'original'),alternate=path.join(f.dir,'alternate'),alias=path.join(f.dir,'active');await mkdir(original);await mkdir(alternate);await writeFile(path.join(original,'target.cjs'),'process.exit(0)','utf8');await writeFile(path.join(alternate,'target.cjs'),'process.exit(99)','utf8');await symlink(original,alias,process.platform==='win32'?'junction':'dir');const manifest=JSON.parse(await readFile(f.file,'utf8'));manifest.argv[1]=path.join(alias,'target.cjs');manifest.target_files=[{path:'original/target.cjs',sha256:sha256(await readFile(path.join(original,'target.cjs'))),role:'target'}];await writeFile(f.file,JSON.stringify(manifest),'utf8');const binding=await bindOracle(f.file);await unlink(alias);await symlink(alternate,alias,process.platform==='win32'?'junction':'dir');const result=await callOracle(binding,sample);expect(result.observation.error?.code).toBe('TARGET_CHANGED');expect(result.actual_calls).toBe(0);}
 finally{await rm(f.dir,{recursive:true,force:true});}
});
for(const [name,script] of [
 ['multiple responses','let t="";process.stdin.on("data",d=>t+=d);process.stdin.on("end",()=>{const q=JSON.parse(t),r=JSON.stringify({protocol_version:1,request_id:q.request_id,status:"ok",outputs:{result:q.inputs.x}});console.log(r);console.log(r);});'],
 ['wrong request identity','console.log(JSON.stringify({protocol_version:1,request_id:"wrong",status:"ok",outputs:{result:{kind:"bv",width:64,bits:"0x0020000000000001"}}}));'],
 ['lossy output type','let t="";process.stdin.on("data",d=>t+=d);process.stdin.on("end",()=>{const q=JSON.parse(t);console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:"ok",outputs:{result:9007199254740993}}));});']
] as const)it(`retains ${name} as protocol failure with one attempted target call`,async()=>{const f=await fixture(script);try{const result=await callOracle(await bindOracle(f.file),sample);expect(result.observation.status).toBe('protocol_error');expect(result.observation.outputs).toEqual({});expect(result.actual_calls).toBe(1);expect(result.execution?.stdout.length).toBeGreaterThan(0);}finally{await rm(f.dir,{recursive:true,force:true});}});
it('retains crash diagnostics and accepts separate stderr logs only',async()=>{
 const f=await fixture('process.stdout.write("unfinished");process.stderr.write("native crashed");process.exit(12);');
 try{const result=await callOracle(await bindOracle(f.file),sample);expect(result.observation.status).toBe('crash');expect(result.execution).toMatchObject({stdout:'unfinished',stderr:'native crashed',code:12});expect(result.actual_calls).toBe(1);}
 finally{await rm(f.dir,{recursive:true,force:true});}
});

it('binds the exact input snapshot even if the caller mutates its sample while identity is checked',async()=>{
 const f=await fixture('let text="";process.stdin.on("data",d=>text+=d);process.stdin.on("end",()=>{const q=JSON.parse(text);console.log(JSON.stringify({protocol_version:1,request_id:q.request_id,status:"ok",outputs:{result:q.inputs.x}}));});');
 try{const binding=await bindOracle(f.file),mutable:any=structuredClone(sample);const pending=callOracle(binding,mutable);mutable.inputs.x.bits='0x0000000000000001';const result=await pending;expect(result.observation.inputs.x).toEqual({kind:'bv',width:64,bits:'0x0020000000000001'});expect(result.observation.outputs.result).toEqual({kind:'bv',width:64,bits:'0x0020000000000001'});}
 finally{await rm(f.dir,{recursive:true,force:true});}
});
