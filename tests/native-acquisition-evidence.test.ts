import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {isoFiletime,validateOwnedCheckpoint,validateAcquisitionRequest,validateProcessIdentity,validateWindowCapture,validateMainCapture,validatePrivateCapture} from '../src/native-acquisition-evidence.js';
import type {NativeTracePlan} from '../src/native-trace.js';
const digest=(data:Buffer)=>createHash('sha256').update(data).digest('hex');
const clone=<T>(value:T):T=>structuredClone(value);
const started='2026-10-19T18:52:41.273Z',created='2026-10-19T18:52:42.6473964Z';
const creation='134369095626473964',observed='2026-10-19T18:52:43.6473964Z',finished='2026-10-19T18:53:48.756Z';
const file='C:\\input\\sample.exe',executable='C:\\case\\.binary-work\\binary_trace_example\\sample.exe';
const sourceSha='a'.repeat(64),plan:NativeTracePlan={duration_ms:60000,breakpoints_rva:[],ranges:[{rva:'0x1000',size_bytes:4}],api_hooks:[],max_events:16};
function invalid(run:()=>unknown){expect(run).toThrow(expect.objectContaining({code:'ACQUISITION_EVIDENCE_INVALID'}));}
function identity(){return {pid:123,executable,creation_filetime:creation,exit_filetime:'0',exit_code:259,alive:true,observed_utc:observed};}
const processExpected=()=>({pid:123,executable,started_at:started,observed_before:finished});
function checkpoint(){return {schema_version:1,status:'failed',is_checkpoint:true,checkpoint_sequence:1,pid:123,frida_version:'fixture',
 events:[{type:'agent_ready',arch:'ia32',pointer_size:4,image_base:'0x400000',image_size:8192,hardware_breakpoints:0,installed_api_hooks:0}],
 snapshots:[],identities:{worker:{file:'trace-worker.py',sha256:'1'.repeat(64),size_bytes:1},agent:{file:'trace-agent.js',sha256:'2'.repeat(64),size_bytes:1},frida:{version:'fixture',module_path:'C:\\fixture'}},
 omitted_events:0,omitted_events_complete:false,hook_states:{initial:[],current:[],final:[]},hook_states_complete:false,
 cleanup:{owned_pid_terminated:false,session_detached:false,windows_job_assigned:true,windows_job_closed:false},error:{code:'TRACE_IN_PROGRESS',message:'Synthetic checkpoint; no process started'}};}
const requestExpected=()=>({file,tool:{command:'C:\\tools\\python.exe',args:['-I','worker.py']},plan,source_sha256:sourceSha,source_size_bytes:1024});
function request(){const expected=requestExpected();return {file:expected.file,tool:clone(expected.tool),plan:clone(expected.plan),source:{path:file,sha256:sourceSha,size_bytes:1024,artifact:{sha256:sourceSha,relative_path:'artifacts/'+sourceSha,media_type:'application/vnd.microsoft.portable-executable',size_bytes:1024}}};}
function windowCapture(){return {schema_version:1,kind:'path_bound_window_inventory',pid:123,executable,process_started_at:created,observed_at:observed,
 scope:'window metadata and bounded WM_GETTEXT only; no clicks or input',inventory:{windows:[{handle:'0x123',parent_handle:null,thread_id:456,process_id:123,class_name:'Synthetic',text:'Fixture only',visible:false,text_query_timed_out:false,text_query_status:'caption',text_query_error_code:null,text_at_buffer_limit:false}],truncated:false}};}
const windowExpected=()=>({...processExpected(),creation_filetime:creation,finished_at:finished});
const mainExpected=()=>({pid:123,executable,creation_filetime:creation,source_sha256:sourceSha,image_base:'0x400000',image_size:8,started_at:started,finished_at:finished});
function mainCapture(partial=false){
 const image=partial?Buffer.from([1,2,3,4,0,0,0,0]):Buffer.from([1,2,3,4,5,6,7,8]);
 const pages=[0,4].map(offset=>{const count=partial&&offset===4?0:4;return {rva:'0x'+offset.toString(16),requested_bytes:4,observed_bytes:count,coverage_complete:count===4,observed_prefix_bytes:count,observed_sha256:count?digest(image.subarray(offset,offset+count)):null,
 attempts:count?[{rva:'0x'+offset.toString(16),requested_bytes:4,transferred_bytes:4,success:true,winerror:0,source:'initial_chunk',transferred_sha256:digest(image.subarray(offset,offset+4)),output_write:{success:true,written_prefix_bytes:4}}]:[]};});
 const value={schema_version:1,status:partial?'partial':'completed',pid:123,base:'0x400000',size_bytes:8,atomic:false,runnable_pe:false,layout:'flat_rva_memory',observation:'cooperative_non_atomic_external_read',unobserved_fill:'zero',zero_fill_is_observed:false,
 started_utc:'2026-10-19T18:52:43.0000000Z',ended_utc:'2026-10-19T18:52:44.0000000Z',limits:{image_bytes:67108864,chunk_bytes:65536,retry_page_bytes:4096,timeout_ms:10000},
 identity:{expected_executable:executable,expected_creation_filetime:creation,start:identity(),end:{...identity(),observed_utc:'2026-10-19T18:52:43.8000000Z'}},tool:{file:'memory-image.py',size_bytes:12,sha256:'b'.repeat(64)},
 coverage:{pages,observed_bytes:partial?4:8,unobserved_bytes:partial?4:0,unverified_output_bytes:0,coverage_complete:!partial,counting:'union_of_observed_prefix_bytes_per_disjoint_rva_extent'},
 image:{file:'main.bin',size_bytes:8,sha256:digest(image),hash_includes_unobserved_zero_fill:true},error:partial?{code:'TIMEOUT',message:'Synthetic partial'}:null,live_header:null,mutable_header_differences:[],cleanup:{process_handle_closed:true,source_handle_closed:true},
 source:{path:executable,sha256:sourceSha,size_bytes:1024,write_delete_sharing_denied:true,verified_stable:true},elapsed_ms:100.125};
 return {image,value};
}

function privateCapture(partial=false){
 const main=Buffer.from([0xe8,0xfd,0xff,0xbf,0x05,0x90,0,0]),bytes=Buffer.alloc(4096,0x90);if(partial)bytes.fill(0,2048);
 const expected={...mainExpected(),callers:['0x0'],main_receipt_sha256:'d'.repeat(64),main_image_sha256:digest(main),helper_sha256:'c'.repeat(64),support_sha256:'b'.repeat(64)};
 const region={base:'0x6000000',allocation_base:'0x6000000',size_bytes:4096,allocation_protect:'0x40',state:'0x1000',protect:'0x40',type:'0x20000',returned_size:48,allocation_fields_defined:true,capture_reason:null};
 const boundary={...region,base:'0x6001000',allocation_base:'0x0',allocation_protect:'0x0',state:'0x10000',protect:'0x1',type:'0x0',allocation_fields_defined:false,capture_reason:'NOT_COMMITTED'};
 const callerRegion={...region,base:'0x400000',allocation_base:'0x400000',size_bytes:8,type:'0x1000000',capture_reason:'NOT_PRIVATE'};
 const query=(address:string,purpose:string,metadata:typeof region)=>({address,purpose,observed_utc:'2026-10-19T18:52:43.7000000Z',region:clone(metadata)});
 const count=partial?2048:4096,coverage={pages:[{rva:'0x0',requested_bytes:4096,observed_bytes:count,coverage_complete:!partial,observed_prefix_bytes:count,observed_sha256:digest(bytes.subarray(0,count)),attempts:[{rva:'0x0',requested_bytes:4096,transferred_bytes:count,success:!partial,winerror:partial?299:0,source:'initial_chunk',transferred_sha256:digest(bytes.subarray(0,count)),output_write:{success:true,written_prefix_bytes:count}}]}],observed_bytes:count,unobserved_bytes:4096-count,unverified_output_bytes:0,coverage_complete:!partial,counting:'union_of_observed_prefix_bytes_per_disjoint_rva_extent'};
 const value={schema_version:1,kind:'bound_private_executable_regions',status:partial?'partial':'completed',atomic:false,runnable_verified:false,scope:'readable_executable_private_regions_of_captured_rel32_targets',
 started_utc:'2026-10-19T18:52:43.0000000Z',ended_utc:'2026-10-19T18:52:44.0000000Z',inputs:{main_receipt:{path:'C:\\out\\main.json',sha256:expected.main_receipt_sha256,size_bytes:1234},main_image:{path:'C:\\out\\main.bin',sha256:expected.main_image_sha256,size_bytes:8},source:{path:executable,sha256:sourceSha,size_bytes:1024,verified_stable:true}},
 tool:{helper:{file:'private-regions.py',sha256:expected.helper_sha256,size_bytes:12},memory_image_support:{file:'memory-image.py',sha256:expected.support_sha256,size_bytes:12}},
 identity:{start:identity(),end:{...identity(),observed_utc:'2026-10-19T18:52:43.8000000Z'},pid:123,expected_executable:executable,expected_creation_filetime:creation},
 callers:[{caller_rva:'0x0',caller_va:'0x400000',expected_bytes:main.subarray(0,6).toString('hex'),target_va:'0x6000002',status:partial?'unknown':'captured',unknown_reason:partial?{code:'TARGET_REGION_PARTIAL',message:'Synthetic partial'}:null,target_region_captured:!partial,live_read:{hex:main.subarray(0,6).toString('hex'),transferred_bytes:6,success:true,winerror:0},target_initial_region:clone(region),allocation_base:region.allocation_base,capture_file:'private-001.bin',allocation_metadata_scan_complete:true}],
 allocations:[{allocation_base:region.allocation_base,caller_indices:[0],metadata_scan_complete:true,regions:[{...clone(region),capture_file:'private-001.bin',byte_capture_status:partial?'partial':'completed'}],byte_scope:'readable_executable_private_regions_only',all_allocation_bytes_captured:false,boundary_region:clone(boundary)}],
 captures:[{file:'private-001.bin',base:region.base,allocation_base:region.allocation_base,size_bytes:4096,status:partial?'partial':'completed',sha256:digest(bytes),coverage,region_at_plan:clone(region),target_caller_indices:[0],unobserved_fill:'zero',zero_fill_is_observed:false,error:null}],queries:[query('0x400000','caller_pre_read',callerRegion),query('0x6000002','target',region),query('0x6000000','allocation_scan',region),query('0x6001000','allocation_scan',boundary),query('0x6000000','pre_read',region)],
 limits:{total_capture_bytes:16777216,allocation_scan_span_bytes:16777216,query_count:4096,callers:16,capture_regions:128,timeout_ms:10000},cleanup:{process_handle_closed:true,source_handle_closed:true,image_handle_closed:true},error:partial?{code:'PARTIAL_CAPTURE',message:'Synthetic partial'}:null,elapsed_ms:10.125,
 totals:{capture_file_bytes:4096,observed_bytes:count,unobserved_bytes:4096-count,query_count:5}};
 return {main,bytes,expected,value,captures:new Map([['private-001.bin',bytes]])};
}

describe('exact native acquisition evidence',()=>{
 it('preserves all seven fractional UTC digits without Number rounding',()=>{
  expect(isoFiletime(created)).toBe(134369095626473964n);
  expect(isoFiletime('2026-10-19T18:52:42.6473965+00:00')).toBe(134369095626473965n);
  expect(isoFiletime('1970-01-01T00:00:00Z')).toBe(116444736000000000n);
 });
 it.each(['2026-02-30T00:00:00Z','2026-10-19T18:52:42.64739641Z','2026-10-19T18:52:42+01:00','2026-10-19 18:52:42Z','2026-10-19T18:52:60Z','1600-01-01T00:00:00Z',123,null])('rejects invalid or inexact UTC timestamp %s',value=>invalid(()=>isoFiletime(value)));
 it('binds a unique passive ia32 ready event through the production checkpoint protocol',()=>{
  const value=checkpoint();const result=validateOwnedCheckpoint(value,plan,{image_size:8192});expect(result).toMatchObject({pid:123,image_base:'0x400000',image_size:8192});expect(result.checkpoint).toEqual(value);
 });
 it.each(['duplicate','noncheckpoint','arch','pointer','hardware','api','overflow','zero','size','job','pid','protocol'] as const)('rejects checkpoint %s mismatch',kind=>{
  const value=checkpoint();
  if(kind==='duplicate')value.events.push(clone(value.events[0]!));
  if(kind==='noncheckpoint')value.is_checkpoint=false;
  if(kind==='arch')value.events[0]!.arch='x64';
  if(kind==='pointer')value.events[0]!.pointer_size=8;
  if(kind==='hardware')value.events[0]!.hardware_breakpoints=1;
  if(kind==='api')value.events[0]!.installed_api_hooks=1;
  if(kind==='overflow')value.events[0]!.image_base='0xfffff001';
  if(kind==='zero')value.events[0]!.image_base='0x0';
  if(kind==='size')value.events[0]!.image_size=4096;
  if(kind==='job')value.cleanup.windows_job_assigned=false;
  if(kind==='pid')value.pid=0;
  if(kind==='protocol')value.checkpoint_sequence=0;
  invalid(()=>validateOwnedCheckpoint(value,plan,{image_size:8192}));
 });
 it('rejects a nonpassive plan even if ready claims zero hooks',()=>invalid(()=>validateOwnedCheckpoint(checkpoint(),{...plan,breakpoints_rva:['0x1000']},{image_size:8192})));
 it('binds the actual job request to file, backend argv, plan and source ArtifactRef',()=>expect(()=>validateAcquisitionRequest(request(),requestExpected())).not.toThrow());
 it.each(['file','source_path','sha','source_size','artifact_hash','artifact_size','artifact_path','artifact_type','tool','plan','injection'] as const)('rejects job request %s substitution',kind=>{
  const value=request();
  if(kind==='file')value.file='C:\\other.exe';
  if(kind==='source_path')value.source.path='C:\\other.exe';
  if(kind==='sha')value.source.sha256='f'.repeat(64);
  if(kind==='source_size')value.source.size_bytes=1025;
  if(kind==='artifact_hash')value.source.artifact.sha256='f'.repeat(64);
  if(kind==='artifact_size')value.source.artifact.size_bytes=1025;
  if(kind==='artifact_path')value.source.artifact.relative_path='../'+sourceSha;
  if(kind==='artifact_type')value.source.artifact.media_type='application/json';
  if(kind==='tool')value.tool.args.push('--unsafe');
  if(kind==='plan')value.plan.ranges[0]!.size_bytes=5;
  if(kind==='injection')Object.assign(value,{pid:123});
  invalid(()=>validateAcquisitionRequest(value,requestExpected()));
 });
 it('validates live process identity and returns the exact creation token',()=>expect(validateProcessIdentity(identity(),processExpected())).toBe(creation));
 it.each(['pid','path','alias','dead','exit','token','token_overflow','before_start','after_observation','reused_pid','observation_before_creation','observation_after_end','injection'] as const)('rejects process identity %s',kind=>{
  const value=identity();let expected:ReturnType<typeof processExpected>&{creation_filetime?:string}=processExpected();
  if(kind==='pid')value.pid=124;
  if(kind==='path')value.executable='C:\\other.exe';
  if(kind==='alias')value.executable=executable.replace('sample.exe','..\\sample.exe');
  if(kind==='dead')value.alive=false;
  if(kind==='exit')value.exit_code=0;
  if(kind==='token')value.creation_filetime='0134369095626473964';
  if(kind==='token_overflow')value.creation_filetime='18446744073709551616';
  if(kind==='before_start')value.creation_filetime='134369095612729999';
  if(kind==='after_observation')value.creation_filetime='134369096287560001';
  if(kind==='reused_pid')expected.creation_filetime='134369095626473965';
  if(kind==='observation_before_creation')value.observed_utc='2026-10-19T18:52:42.6473963Z';
  if(kind==='observation_after_end')value.observed_utc='2026-10-19T18:53:48.7560001Z';
  if(kind==='injection')Object.assign(value,{owned:true});
  invalid(()=>validateProcessIdentity(value,expected));
 });
 it('accepts a window inventory with zero windows and precise creation binding',()=>{
  const value=windowCapture();value.inventory.windows=[];expect(()=>validateWindowCapture(value,windowExpected())).not.toThrow();
 });
 it('accepts actual bounded window metadata without interpreting UI text',()=>expect(()=>validateWindowCapture(windowCapture(),windowExpected())).not.toThrow());
 it.each(['fraction','before_start','after_end','kind','row_owner','text','count','injection'] as const)('rejects window %s mismatch',kind=>{
  const value=windowCapture();
  if(kind==='fraction')value.process_started_at='2026-10-19T18:52:42.6473965Z';
  if(kind==='before_start')value.observed_at='2026-10-19T18:52:41.0000000Z';
  if(kind==='after_end')value.observed_at='2026-10-19T18:53:48.7560001Z';
  if(kind==='kind')value.kind='any_process_windows';
  if(kind==='row_owner')value.inventory.windows[0]!.process_id=124;
  if(kind==='text')value.inventory.windows[0]!.text='x'.repeat(513);
  if(kind==='count')value.inventory.windows=Array.from({length:257},()=>clone(value.inventory.windows[0]!));
  if(kind==='injection')Object.assign(value,{restored:true});
  invalid(()=>validateWindowCapture(value,windowExpected()));
 });
 it('accepts complete observed image bytes with source and closed HANDLE identity',()=>{
  const {value,image}=mainCapture();expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:true,observed_bytes:8,unobserved_bytes:0});
 });
 it('keeps legitimate zero-filled unread image suffixes explicitly partial',()=>{
  const {value,image}=mainCapture(true);expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:false,observed_bytes:4,unobserved_bytes:4});
 });
 it.each(['image_hash','prefix_hash','gap','overlap','total','promote','placeholder','open_handle','source','token','time','overflow','scope','zero_success','injection'] as const)('rejects image %s mismatch',kind=>{
  const f=mainCapture(kind==='placeholder'||kind==='promote'||kind==='zero_success');const {value,image}=f;
  if(kind==='image_hash')value.image.sha256='0'.repeat(64);
  if(kind==='prefix_hash')value.coverage.pages[0]!.observed_sha256='0'.repeat(64);
  if(kind==='gap')value.coverage.pages[1]!.rva='0x5';
  if(kind==='overlap')value.coverage.pages[1]!.rva='0x3';
  if(kind==='total')value.coverage.observed_bytes=7;
  if(kind==='promote')value.status='completed';
  if(kind==='placeholder'){image[7]=99;value.image.sha256=digest(image);}
  if(kind==='open_handle')value.cleanup.source_handle_closed=false;
  if(kind==='source')value.source.sha256='f'.repeat(64);
  if(kind==='token')value.identity.end.creation_filetime='134369095626473965';
  if(kind==='time')value.identity.end.observed_utc='2026-10-19T18:52:44.0000001Z';
  if(kind==='overflow')value.base='0xfffffffc';
  if(kind==='scope')value.zero_fill_is_observed=true;
  if(kind==='zero_success'){value.status='completed';value.coverage.pages.forEach(row=>{row.observed_bytes=0;row.observed_prefix_bytes=0;row.observed_sha256=null;row.coverage_complete=false;row.attempts=[];});image.fill(0);value.image.sha256=digest(image);value.coverage.observed_bytes=0;value.coverage.unobserved_bytes=8;value.coverage.coverage_complete=false;}
  if(kind==='injection')Object.assign(value,{runnable_verified:true});
  invalid(()=>validateMainCapture(value,image,mainExpected()));
 });
 it('rejects live checkpoints without imported collector/runtime origin identities',()=>{
  const value=checkpoint();Object.assign(value.identities,{worker:null,agent:null,frida:null});
  invalid(()=>validateOwnedCheckpoint(value,plan,{image_size:8192}));
 });
 it('rejects an ownership failure hidden behind a partial timeout additional error',()=>{
  const {value,image}=mainCapture(true);Object.assign(value,{additional_errors:[{code:'PROCESS_IDENTITY_MISMATCH',message:'Synthetic mismatch after timeout'}]});
  invalid(()=>validateMainCapture(value,image,mainExpected()));
 });
 it('retains a legitimate all-unread image as zero observed bytes, never success',()=>{
  const {value,image}=mainCapture(true);image.fill(0);value.image.sha256=digest(image);
  value.coverage.pages.forEach(row=>{row.observed_bytes=0;row.observed_prefix_bytes=0;row.observed_sha256=null;row.coverage_complete=false;row.attempts=[];});
  value.coverage.observed_bytes=0;value.coverage.unobserved_bytes=8;
  expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:false,observed_bytes:0,unobserved_bytes:8});
 });
 it('retains a partial capture that ended with a precisely observed process exit',()=>{
  const {value,image}=mainCapture(true);Object.assign(value.identity.end,{alive:false,exit_code:0,exit_filetime:'134369095637000000'});
  expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:false,observed_bytes:4,unobserved_bytes:4});
 });
 it('does not claim partially overwritten unverified output bytes as observations',()=>{
  const {value,image}=mainCapture(true);image[7]=99;value.image.sha256=digest(image);Object.assign(value.coverage.pages[1]!,{output_bytes_unverified:true});
  value.coverage.unverified_output_bytes=4;value.unobserved_fill='zero_except_unverified_output_write_ranges';
  expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:false,observed_bytes:4,unobserved_bytes:4});
 });
 it('rejects observed prefixes with no read attempt evidence',()=>{
  const {value,image}=mainCapture();value.coverage.pages[0]!.attempts=[];
  invalid(()=>validateMainCapture(value,image,mainExpected()));
 });

 it('binds private executable bytes to the current main caller and same-handle reread',()=>{
  const f=privateCapture();expect(validatePrivateCapture(f.value,f.captures,f.main,f.expected)).toEqual({complete:true,observed_bytes:4096,unobserved_bytes:0});
 });
 it('retains a private region partial read without claiming closure',()=>{
  const f=privateCapture(true);expect(validatePrivateCapture(f.value,f.captures,f.main,f.expected)).toEqual({complete:false,observed_bytes:2048,unobserved_bytes:2048});
 });
 it.each(['helper','support','receipt','image','source','token','cleanup','caller','derived_target','live_bytes','path','hash','coverage','totals','out_of_region','extra_buffer','error','scan','duplicate','initial_region','scan_error','allocation_link','caller_scan'] as const)('rejects private %s mismatch',kind=>{
  const f=privateCapture(),value=f.value;
  if(kind==='helper')value.tool.helper.sha256='f'.repeat(64);
  if(kind==='support')value.tool.memory_image_support.sha256='f'.repeat(64);
  if(kind==='receipt')value.inputs.main_receipt.sha256='f'.repeat(64);
  if(kind==='image')f.main[7]=1;
  if(kind==='source')value.inputs.source.verified_stable=false;
  if(kind==='token')value.identity.end.creation_filetime='134369095626473965';
  if(kind==='cleanup')value.cleanup.image_handle_closed=false;
  if(kind==='caller')value.callers[0]!.caller_rva='0x1';
  if(kind==='derived_target')value.callers[0]!.target_va='0x6000003';
  if(kind==='live_bytes')value.callers[0]!.live_read.hex='e80000000090';
  if(kind==='path')value.captures[0]!.file='../private-001.bin';
  if(kind==='hash')value.captures[0]!.sha256='f'.repeat(64);
  if(kind==='coverage')value.captures[0]!.coverage.pages[0]!.observed_sha256='f'.repeat(64);
  if(kind==='totals')value.totals.observed_bytes=4095;
  if(kind==='out_of_region')value.captures[0]!.base='0x6100000';
  if(kind==='extra_buffer')f.captures.set('private-002.bin',Buffer.alloc(4));
  if(kind==='error')value.error={code:'PROCESS_IDENTITY_MISMATCH',message:'Synthetic mismatch'};
  if(kind==='scan')value.allocations[0]!.metadata_scan_complete=false;
  if(kind==='duplicate')value.captures.push(clone(value.captures[0]!));
  if(kind==='initial_region')value.callers[0]!.target_initial_region.base='0x6100000';
  if(kind==='scan_error')Object.assign(value.allocations[0]!,{scan_error:{code:'QUERY_FAILED',message:'Synthetic metadata scan error'}});
  if(kind==='allocation_link')value.allocations[0]!.caller_indices=[];
  if(kind==='caller_scan')value.callers[0]!.allocation_metadata_scan_complete=false;
  invalid(()=>validatePrivateCapture(value,f.captures,f.main,f.expected));
 });

 it('retains a legitimate unknown private target without manufacturing a capture file',()=>{
  const f=privateCapture(true),caller=f.value.callers[0]!;
  caller.unknown_reason={code:'NOT_PRIVATE',message:'Synthetic unobserved destination'};
  for(const key of ['target_initial_region','allocation_base','capture_file','allocation_metadata_scan_complete'])delete (caller as unknown as Record<string,unknown>)[key];
  f.value.allocations=[];f.value.captures=[];f.value.queries=[];f.captures.clear();f.value.totals={capture_file_bytes:0,observed_bytes:0,unobserved_bytes:0,query_count:0};
  expect(validatePrivateCapture(f.value,f.captures,f.main,f.expected)).toEqual({complete:false,observed_bytes:0,unobserved_bytes:0});
 });

 it('rejects a window capture even when an invalid expected PID also equals zero',()=>{
  const value=windowCapture();value.pid=0;value.inventory.windows=[];
  invalid(()=>validateWindowCapture(value,{...windowExpected(),pid:0}));
 });

 it.each([0,2,4,null,'absent'] as const)('rejects complete bytes unsupported by persisted output write %s',written=>{
  const {value,image}=mainCapture(),attempt=value.coverage.pages[0]!.attempts[0]!;
  if(written==='absent')delete (attempt as unknown as Record<string,unknown>).output_write;
  else Object.assign(attempt,{output_write:{success:false,written_prefix_bytes:written}});
  invalid(()=>validateMainCapture(value,image,mainExpected()));
 });
 it('retains only the successfully persisted prefix after a short output write',()=>{
  const {value,image}=mainCapture(true),page=value.coverage.pages[0]!;image[2]=0;image[3]=0;value.image.sha256=digest(image);
  page.observed_bytes=2;page.observed_prefix_bytes=2;page.observed_sha256=digest(image.subarray(0,2));page.coverage_complete=false;
  Object.assign(page.attempts[0]!,{output_write:{success:false,written_prefix_bytes:2}});
  value.coverage.observed_bytes=2;value.coverage.unobserved_bytes=6;
  expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:false,observed_bytes:2,unobserved_bytes:6});
 });
 it('keeps the initial persisted suffix when a retry overwrites a shorter prefix',()=>{
  const {value}=mainCapture(true),image=Buffer.from([9,8,3,4,0,0,0,0]);
  const initial={rva:'0x0',requested_bytes:8,transferred_bytes:4,success:false,winerror:299,source:'initial_chunk',transferred_sha256:digest(Buffer.from([1,2,3,4])),output_write:{success:true,written_prefix_bytes:4}};
  const retry={rva:'0x0',requested_bytes:8,transferred_bytes:2,success:false,winerror:299,source:'page_retry',transferred_sha256:digest(Buffer.from([9,8])),output_write:{success:true,written_prefix_bytes:2}};
  Object.assign(value.coverage,{pages:[{rva:'0x0',requested_bytes:8,observed_bytes:4,observed_prefix_bytes:4,observed_sha256:digest(image.subarray(0,4)),coverage_complete:false,attempts:[initial,retry]}]});
  value.image.sha256=digest(image);
  expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:false,observed_bytes:4,unobserved_bytes:4});
 });

 it.each([0,2,null,'absent'] as const)('rejects a partial observer overstating persisted prefix %s',written=>{
  const {value,image}=mainCapture(true),attempt=value.coverage.pages[0]!.attempts[0]!;
  if(written==='absent')delete (attempt as unknown as Record<string,unknown>).output_write;
  else Object.assign(attempt,{output_write:{success:false,written_prefix_bytes:written}});
  invalid(()=>validateMainCapture(value,image,mainExpected()));
 });
 it('allows a full page retry to repair a short initial RPM when both writes succeeded',()=>{
  const {value,image}=mainCapture(),initial={rva:'0x0',requested_bytes:8,transferred_bytes:4,success:false,winerror:299,source:'initial_chunk',transferred_sha256:digest(image.subarray(0,4)),output_write:{success:true,written_prefix_bytes:4}},retry={rva:'0x0',requested_bytes:8,transferred_bytes:8,success:true,winerror:0,source:'page_retry',transferred_sha256:digest(image),output_write:{success:true,written_prefix_bytes:8}};
  Object.assign(value.coverage,{pages:[{rva:'0x0',requested_bytes:8,observed_bytes:8,observed_prefix_bytes:8,observed_sha256:digest(image),coverage_complete:true,attempts:[initial,retry]}]});
  expect(validateMainCapture(value,image,mainExpected())).toEqual({complete:true,observed_bytes:8,unobserved_bytes:0});
 });

 it.each(['inventory','regions','boundary','scans','region_scan','boundary_scan','type','protect','boundary_gap','same_allocation_boundary'] as const)('rejects private scan inventory %s contradiction',kind=>{
  const f=privateCapture(),allocation=f.value.allocations[0]!;
  if(kind==='inventory'){allocation.regions=[];delete (allocation as unknown as Record<string,unknown>).boundary_region;f.value.queries=[];}
  if(kind==='regions')allocation.regions=[];
  if(kind==='boundary')delete (allocation as unknown as Record<string,unknown>).boundary_region;
  if(kind==='scans')f.value.queries=f.value.queries.filter(row=>row.purpose!=='allocation_scan');
  if(kind==='region_scan')f.value.queries=f.value.queries.filter(row=>!(row.purpose==='allocation_scan'&&row.address==='0x6000000'));
  if(kind==='boundary_scan')f.value.queries=f.value.queries.filter(row=>!(row.purpose==='allocation_scan'&&row.address==='0x6001000'));
  if(kind==='type')allocation.regions[0]!.type='0x1000000';
  if(kind==='protect')allocation.regions[0]!.protect='0x1';
  if(kind==='boundary_gap'){allocation.boundary_region.base='0x6002000';const query=f.value.queries.find(row=>row.purpose==='allocation_scan'&&row.address==='0x6001000')!;query.address='0x6002000';query.region.base='0x6002000';}
  if(kind==='same_allocation_boundary'){Object.assign(allocation.boundary_region,{allocation_base:'0x6000000',allocation_protect:'0x40',state:'0x1000',protect:'0x40',type:'0x20000',allocation_fields_defined:true,capture_reason:null});const query=f.value.queries.find(row=>row.purpose==='allocation_scan'&&row.address==='0x6001000')!;query.region=clone(allocation.boundary_region);}
  f.value.totals.query_count=f.value.queries.length;
  invalid(()=>validatePrivateCapture(f.value,f.captures,f.main,f.expected));
 });
 it('accepts a contiguous allocation scan that also describes an uncaptured nonexecutable region',()=>{
  const f=privateCapture(),allocation=f.value.allocations[0]!,region={...clone(allocation.regions[0]!),base:'0x6001000',protect:'0x2',capture_reason:'NOT_EXECUTABLE'};
  delete (region as unknown as Record<string,unknown>).capture_file;delete (region as unknown as Record<string,unknown>).byte_capture_status;
  allocation.regions.push(region);allocation.boundary_region.base='0x6002000';
  const old=f.value.queries[3]!;
  f.value.queries.splice(3,1,{...old,region:clone(region)},{...old,address:'0x6002000',region:clone(allocation.boundary_region)});
  f.value.totals.query_count=f.value.queries.length;
  expect(validatePrivateCapture(f.value,f.captures,f.main,f.expected)).toEqual({complete:true,observed_bytes:4096,unobserved_bytes:0});
 });

});