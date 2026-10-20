import {it,expect} from 'vitest';
import {mkdtemp,readFile,writeFile,rm,symlink,mkdir} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {CaseStore} from '../src/store.js';
import {exportReport} from '../src/reporting.js';
import {runProcess} from '../src/process.js';

async function scenario(run:(store:CaseStore,dir:string)=>Promise<void>){
 const dir=await mkdtemp(path.join(os.tmpdir(),'wirefit-ida-export-'));
 const store=await CaseStore.create(path.join(dir,'case'));
 try{await run(store,dir);}finally{await store.close();const selected=path.resolve(dir);if(path.dirname(selected)!==path.resolve(os.tmpdir())||!path.basename(selected).startsWith('wirefit-ida-export-'))throw new Error('Unsafe cleanup');await rm(selected,{recursive:true,force:true});}
}
async function populate(store:CaseStore){
 const input=await store.putArtifact(Buffer.from('source fixture, never executed','utf8'),'application/octet-stream');
 const raw=await store.putJson({pseudocode:'int f(){return 7;}',untrusted:{sha256:'a'.repeat(64),relative_path:'../../private',size_bytes:8,media_type:'application/json'}});
 const result={result_id:'ida_fixture',operation:'analyze_ida',status:'partial',source:{path:'fixture.exe',sha256:input.sha256,size_bytes:input.size_bytes,artifact:input},provider:{id:'ida',version:'9.3',server:'fixture',revision:'f'.repeat(40)},database:{identity_verified:true},queries:[{query:{kind:'function',address:'0x401000'},status:'partial',error:{code:'NO_DECOMPILER',message:'No decompiler'},artifacts:[raw]}],artifacts:[input,raw],validation:{source_unchanged:true,runnable_verified:false,whole_program_equivalence:false},cleanup:{owned:true,process_closed:true,idb_closed:true}};
 await store.putObject('runs','ida_fixture',{result,request:{file:'fixture.exe',queries:[{kind:'function',address:'0x401000'}]}});
 return {input,raw};
}
it('exports a standalone hashed IDA evidence package without following raw upstream references',async()=>scenario(async(store,dir)=>{
 const {raw}=await populate(store),output=path.join(dir,'export');const manifest=await exportReport(store,'ida_fixture',output);
 expect(manifest.files.some(file=>file.relative_path==='artifacts/'+raw.sha256)).toBe(true);
 const report=await readFile(path.join(output,'report.md'),'utf8');expect(report).toContain('partial');expect(report).toContain('not established');
 const verify=await runProcess(process.execPath,[path.join(output,'verify.mjs')],{timeout_ms:10000});
 expect(verify.code).toBe(0);expect(JSON.parse(verify.stdout)).toMatchObject({original_operation:'analyze_ida',original_status:'partial',target_execution:'not_run',runnable_verified:false});
 await writeFile(path.join(output,'artifacts',raw.sha256),'changed','utf8');
 const damaged=await runProcess(process.execPath,[path.join(output,'verify.mjs')],{timeout_ms:10000});expect(damaged.code).not.toBe(0);
}));
it('rejects export through directory aliases before writing',async()=>scenario(async(store,dir)=>{
 await populate(store);const target=path.join(dir,'private');await mkdir(target);const linked=path.join(dir,'alias');await symlink(target,linked,'junction');
 await expect(exportReport(store,'ida_fixture',path.join(linked,'export'))).rejects.toMatchObject({code:'EXPORT_PATH_INVALID'});
}));
