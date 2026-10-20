import {afterEach, describe, expect, it} from 'vitest';
import {mkdtemp, mkdir, readFile, rm, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {ResearchArchive} from '../src/web/research.js';

const roots:string[]=[];
const base='artifacts/research/vmde/';
async function fixture(){const root=await mkdtemp(path.join(tmpdir(),'wirefit-research-'));roots.push(root);return root;}
async function put(root:string,file:string,value:unknown){const target=path.join(root,file);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,typeof value==='string'?value:JSON.stringify(value),'utf8');}
async function traceFixture(root:string,dir:string,pid:number,status='completed'){
  const raw={pid,status,events:[{type:'module_inventory',modules:[{name:'candidate.exe',base:'0x400000'}]},{type:'api_enter',symbol:'GetStartupInfoA',thread_id:5,context:{eip:'0x7000'},stack:{hex:'01020304'},pc_code:{hex:'90'},return_address:{address:'0x4b10ce'}},{type:'exception',thread_id:5,context:{pc:'0xaa35de'},exception:{type:'access-violation'}}],snapshots:[],error:status==='failed'?{code:'HOOK_FAILED'}:null};
  const text=JSON.stringify(raw),sha=createHash('sha256').update(text,'utf8').digest('hex');
  await put(root,base+dir+'/case/artifacts/'+sha,text);
  await put(root,base+dir+'/process-receipt.json',{started_at:'2026-10-19T23:13:36Z',cli_result:{job:{job_id:'job_'+pid,status},result:{status,trace_artifact:{sha256:sha,relative_path:'artifacts/'+sha,media_type:'application/vnd.wirefit.native-trace+json',size_bytes:Buffer.byteLength(text,'utf8')},snapshots:[]}}});
}
async function nativeFixture(root:string){
  await put(root,base+'native-kernel/native-summary.json',{status:'native_sampled_contract_matched',original_calls:3,original_matched:2,original_failed:1,original_unattempted:0,compiled_control_calls:8,runs:[],whole_program_equivalence:false,runnable_verified:false});
  for(const [profile,rows] of [['edges8',[{id:'edge-a',status:'matched',observed_values:2},{id:'edge-b',status:'mismatched',observed_values:2}]],['legacy896',[{id:'legacy-a',status:'matched',observed_values:1}]]] as const){
    await put(root,base+`native-kernel/comparison-${profile}.json`,{status:'sampled_contract_matched',counts:{declared:rows.length,matched:profile==='edges8'?1:1,mismatched:profile==='edges8'?1:0,failed:0,unattempted:0},comparisons:rows});
    await put(root,base+`native-kernel/release-files/runs/${profile}/native-result.json`,{profile,status:'completed',rows:rows.map((r,i)=>({id:r.id,status:'completed',output:[i,6],evidence:{output_hex:'0000000006000000',registers:{eax_incidental:8},before:{entry:'0x498a50'}}}))});
    await put(root,base+`native-kernel/${profile}.json`,{cases:rows.map(r=>({id:r.id,width:2,height:2,labels:[0,0,0,0]}))});
  }
}
afterEach(async()=>{await Promise.all(roots.splice(0).map(root=>rm(root,{recursive:true,force:true})));});

describe('curated readonly research archive',()=>{
  it('enforces graph budgets inside one oversized target list and caller expansion',async()=>{
    const root=await fixture();await put(root,base+'grid-kernel-analysis/run-ayl3ui/00498a50.json',{listing:[{va:'0x00498a50',flow_type:'COMPUTED_CALL',targets:Array.from({length:1000},(_,i)=>'0x'+(0x500000+i*16).toString(16))}]});
    await put(root,base+'algorithm-candidates/run-1QAnNQ/00499eb0.json',{listing:Array.from({length:1000},(_,i)=>({va:'0x'+(0x499eb0+i*5).toString(16),flow_type:'UNCONDITIONAL_CALL',text:'CALL 0x00498a50'}))});
    const detail=await new ResearchArchive(root).function('grid-498a50');expect(detail.graph.nodes.length).toBeLessThanOrEqual(32);expect(detail.graph.edges.length).toBeLessThanOrEqual(32);expect(detail.limitations.join(' ')).toMatch(/截断/);
  });
  it('does not retain native or CPU success labels when their validation evidence is missing',async()=>{
    const root=await fixture();await put(root,base+'grid-kernel-analysis/run-ayl3ui/00498a50.json',{listing:[{va:'0x00498a50',text:'RET'}]});
    const archive=new ResearchArchive(root),overview=await archive.overview(),entry=overview.functions.find(f=>f.id==='grid-498a50')!;
    expect(entry.status).toBe('static-only');expect(entry.description).not.toContain('904');
    const detail=await archive.function('grid-498a50');expect(detail.description).not.toContain('904');
    expect(overview.functions.find(f=>f.id==='node-record-480230')?.status).not.toBe('cpu-replay');
  });
  it('keeps absent evidence unavailable rather than reporting zero native successes',async()=>{
    const archive=new ResearchArchive(await fixture());const overview=await archive.overview();
    expect(overview.validations.find(v=>v.id==='native-grid')).toMatchObject({status:'unavailable',counts:{}});
    expect(overview.metrics.find(m=>m.label.includes('原生'))?.value).toBe('不可用');
    expect(overview.limitations.join(' ')).toMatch(/可运行|runnable/);
  });
  it('pages saved original comparisons, excludes compiled controls and preserves actual outputs',async()=>{
    const root=await fixture();await nativeFixture(root);const archive=new ResearchArchive(root);
    const page=await archive.validation('native-grid',{offset:1,limit:1});
    expect(page.total).toBe(3);expect(page.items[0]).toMatchObject({id:'edge-b',status:'mismatched',profile:'edges8',original_output:[1,6],candidate_output:null});
    expect(page.validation.counts).toMatchObject({original_calls:3,original_matched:2,compiled_control_calls:8});
    expect(page.validation.scope).toMatch(/synthetic|合成/);
    const failed=await archive.validation('native-grid',{status:'mismatched'});expect(failed.items.map(r=>r.id)).toEqual(['edge-b']);
    expect((await archive.validation('native-grid',{offset:999,limit:3})).items).toEqual([]);
  });
  it('does not upgrade an absent native observation into matched evidence',async()=>{
    const root=await fixture();await nativeFixture(root);await rm(path.join(root,base+'native-kernel/release-files/runs/edges8/native-result.json'));
    const page=await new ResearchArchive(root).validation('native-grid',{});
    expect(page.validation.status).toBe('partial');expect(page.items[0]).toMatchObject({comparison_status:'matched',status:'unavailable',original_output:null});
  });
  it('keeps runs and PIDs separate while exposing registers, stack, code and original indexes',async()=>{
    const root=await fixture();await traceFixture(root,'startup-compat/exit-probe-v7',15508);await traceFixture(root,'startup-compat',999);
    const archive=new ResearchArchive(root);const page=await archive.trace('startup-exit-v7',{type:'api',q:'GetStartup',limit:1});
    expect(page.trace.pid).toBe(15508);expect(page.trace.event_count).toBe(3);expect(page.total).toBe(1);
    expect(page.items[0]).toMatchObject({index:1,type:'api_enter',thread_id:5,address:'0x7000',context:{eip:'0x7000'},stack:{hex:'01020304'},code:{hex:'90'}});
    expect((await archive.trace('startup-compat',{})).trace.pid).toBe(999);
  });
  it('retains failed source trace status and rejects malformed trace references',async()=>{
    const root=await fixture();await traceFixture(root,'startup-compat/exit-probe-v7',15,'failed');const archive=new ResearchArchive(root);
    expect((await archive.trace('startup-exit-v7',{})).trace.status).toBe('failed');
    await put(root,base+'startup-compat/process-receipt.json',{cli_result:{result:{status:'completed',trace_artifact:{sha256:'a'.repeat(64),relative_path:'../../outside.json',size_bytes:2}}}});
    expect((await archive.trace('startup-compat',{})).trace.status).toBe('unavailable');
  });
  it('labels emulator rows separately and does not claim native execution or model proof',async()=>{
    const root=await fixture();await put(root,base+'node-records/run-cpu-writer-20261020/result.json',{status:'completed',observation_kind:'bounded_cpu_emulation',native_call:false,counts:{completed:1,failed:0,unattempted:0},rows:[{id:'node-a',status:'completed',actual_after_hex:'aaff',expected_sha256:'0'.repeat(64),comparison:{matched:true},checks:{all_storage_matches:true}}]});
    const page=await new ResearchArchive(root).validation('node-record-cpu',{});
    expect(page.validation.kind).toBe('cpu-replay');expect(page.validation.scope).toMatch(/CPU/);expect(page.items[0]).toMatchObject({id:'node-a',original_output:'aaff',status:'matched'});
  });
  it('loads observer samples only from the one fixed observation folder and keeps unknown export type',async()=>{
    const root=await fixture();const folder=base+'runtime-export-observer/export-observations-20261020-a/';
    await put(root,folder+'result.json',{status:'completed',request:{pid:35},identity:{start:{pid:35}},samples:[{index:0,status:'completed',file:'sample-000.json'},{index:1,status:'completed',file:'../../outside.json'}]});
    await put(root,folder+'sample-000.json',{index:0,identity:{pid:35},started_utc:'2026-10-19Z',inspection:{status:'completed',frida_export_type:null,exports:[{name:'QSettings',lookup_status:'resolved',matches:[{runtime_executable:true}]}]}});
    const page=await new ResearchArchive(root).trace('runtime-exports',{});
    expect(page.total).toBe(2);expect(page.trace.pid).toBe(35);expect(page.items[0].details).toMatchObject({inspection:{frida_export_type:null}});
    expect(page.items[1].details).toMatchObject({status:'unavailable'});expect(page.trace.status).toBe('partial');
  });
  it('registers only opaque evidence IDs, returns identity and caps UTF-8 previews',async()=>{
    const root=await fixture();const text='中文'.repeat(40000);await put(root,base+'kernel-replay/candidate.py',text);
    const archive=new ResearchArchive(root);const detail=await archive.function('grid-498a50');const source=detail.sources.find(s=>s.path.endsWith('candidate.py'))!;
    expect(source.id).toMatch(/^ev_[a-f0-9]{24}$/);expect(source.sha256).toBe(createHash('sha256').update(text,'utf8').digest('hex'));expect(source.size_bytes).toBe(240000);expect(source.truncated).toBe(true);expect(source.text).not.toContain('�');expect(Buffer.byteLength(source.text,'utf8')).toBeLessThanOrEqual(96*1024);
    expect((await archive.evidence(source.id)).sha256).toBe(source.sha256);
    await expect(archive.evidence('../../kernel-replay/candidate.py')).rejects.toMatchObject({code:'NOT_FOUND'});
  });
  it('rejects symlinked evidence that escapes the archive root',async()=>{
    const root=await fixture(),external=await fixture();await put(external,'candidate.py','outside secret');await mkdir(path.join(root,base),{recursive:true});await symlink(external,path.join(root,base+'kernel-replay'),process.platform==='win32'?'junction':'dir');
    const detail=await new ResearchArchive(root).function('grid-498a50');expect(detail.sources).toEqual([]);expect(detail.limitations.join(' ')).toMatch(/不可用|unavailable/);
  });
  it('rejects malformed JSON, bogus identifiers and unbounded paging inputs',async()=>{
    const root=await fixture();await put(root,base+'native-kernel/native-summary.json','{"original_calls":');const archive=new ResearchArchive(root);
    expect((await archive.overview()).validations.find(v=>v.id==='native-grid')?.status).toBe('unavailable');
    for(const query of [{limit:0},{offset:-1},{limit:501},{offset:NaN},{q:'x'.repeat(257)}])await expect(archive.trace('startup-exit-v7',query)).rejects.toMatchObject({code:'INVALID_QUERY'});
    await expect(archive.function('not-registered')).rejects.toMatchObject({code:'NOT_FOUND'});
    await expect(archive.validation('__proto__',{})).rejects.toMatchObject({code:'NOT_FOUND'});
  });
  it('reads frozen Ghidra listing addresses without assigning model node identities',async()=>{
    const root=await fixture();await put(root,base+'grid-kernel-analysis/run-ayl3ui/00498a50.json',{listing:[{va:'0x00498a50',bytes:'83ec08',text:'SUB ESP,0x8'}]});await put(root,base+'grid-kernel-analysis/run-ayl3ui/00498a50.c','void FUN_00498a50(void) {}');
    const detail=await new ResearchArchive(root).function('grid-498a50');expect(detail.instructions).toEqual([{address:'0x00498a50',bytes:'83ec08',text:'SUB ESP,0x8'}]);expect(detail.graph.nodes.some(n=>n.address==='0x00498a50')).toBe(true);expect(detail.limitations.join(' ')).toMatch(/节点|node/);
    expect(await readFile(path.join(root,base+'grid-kernel-analysis/run-ayl3ui/00498a50.c'),'utf8')).toBe('void FUN_00498a50(void) {}');
  });
  it('builds only observed local caller edges and excludes unrelated calls',async()=>{
    const root=await fixture();await put(root,base+'algorithm-candidates/run-1QAnNQ/00499eb0.json',{entry_va:'0x00499eb0',listing:[{va:'0x00499f17',flow_type:'UNCONDITIONAL_CALL',text:'CALL 0x00498a50'},{va:'0x00499fa7',flow_type:'UNCONDITIONAL_CALL',text:'CALL 0x00480230'},{va:'0x00499ee6',flow_type:'UNCONDITIONAL_CALL',text:'CALL 0x00481950'}]});
    const detail=await new ResearchArchive(root).function('grid-498a50');
    expect(detail.graph.edges).toContainEqual({from:'caller-499eb0',to:'grid-498a50',label:'static CALL @ 0x00499f17'});
    expect(detail.graph.nodes.map(n=>n.address)).not.toContain('0x00481950');
  });
  it('decodes frozen Capstone text and shows a byte-bound v7 PUSH/JMP without inventing later control edges',async()=>{
    const root=await fixture();await put(root,base+'runtime-export-observer/protected-continuation-static.json',{dispatcher_listing:{instructions:[{va:'0xaa35de',bytes:'9c',mnemonic:'pushfd',operands:''}]}});
    await traceFixture(root,'startup-compat/exit-probe-v7',15);
    const detail=await new ResearchArchive(root).function('startup-transition');
    expect(detail.instructions[0]).toEqual({address:'0xaa35de',bytes:'9c',text:'pushfd'});
    expect(detail.limitations.join(' ')).toMatch(/静态|static/);
  });
  it('rejects nested observer identity from another process even when sample index agrees',async()=>{
    const root=await fixture(),folder=base+'runtime-export-observer/export-observations-20261020-a/';
    await put(root,folder+'result.json',{status:'completed',identity:{start:{pid:35,creation_filetime:'123'}},samples:[{index:0,status:'completed',file:'sample-000.json'}]});
    await put(root,folder+'sample-000.json',{index:0,identity:{start:{pid:36,creation_filetime:'123'},end:{pid:36,creation_filetime:'123'}},inspection:{status:'completed'}});
    const page=await new ResearchArchive(root).trace('runtime-exports',{});expect(page.trace.status).toBe('partial');expect(page.items[0].details).toMatchObject({status:'unavailable'});
  });
  it('refuses raw trace bytes that no longer match the receipt digest',async()=>{
    const root=await fixture();await traceFixture(root,'startup-compat/exit-probe-v7',15);const receipt=JSON.parse(await readFile(path.join(root,base+'startup-compat/exit-probe-v7/process-receipt.json'),'utf8'));
    await put(root,base+'startup-compat/exit-probe-v7/case/'+receipt.cli_result.result.trace_artifact.relative_path,{status:'completed',pid:999,events:[]});
    const page=await new ResearchArchive(root).trace('startup-exit-v7',{});expect(page.trace.status).toBe('unavailable');expect(page.trace.pid).toBeNull();expect(page.items).toEqual([]);
  });
  it('never treats a failed original invocation as a matching output despite a saved comparison claim',async()=>{
    const root=await fixture();await nativeFixture(root);
    await put(root,base+'native-kernel/release-files/runs/edges8/native-result.json',{profile:'edges8',status:'failed',rows:[{id:'edge-a',status:'failed',error:{code:'CAPTURE_FAILED'}},{id:'edge-b',status:'completed'}]});
    const page=await new ResearchArchive(root).validation('native-grid',{});
    expect(page.items[0]).toMatchObject({id:'edge-a',status:'failed',comparison_status:'matched',original_output:null});
    expect(page.items[1]).toMatchObject({id:'edge-b',status:'unavailable',original_output:null});expect(page.validation.status).toBe('partial');
  });
  it('preserves a raw worker failure even if the public envelope claims completion',async()=>{
    const root=await fixture();await traceFixture(root,'startup-compat/exit-probe-v7',15,'failed');
    const rel=base+'startup-compat/exit-probe-v7/process-receipt.json',receipt=JSON.parse(await readFile(path.join(root,rel),'utf8'));receipt.cli_result.result.status='completed';await put(root,rel,receipt);
    expect((await new ResearchArchive(root).trace('startup-exit-v7',{})).trace.status).toBe('failed');
  });
});
