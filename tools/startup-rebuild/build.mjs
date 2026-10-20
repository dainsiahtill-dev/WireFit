import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readStable,absolute,absent,newDir,writeNew,jsonBytes,sha} from '../../artifacts/research/vmde/native-kernel/io.mjs';
import {patchCompatibilityStartup,SOURCE_SHA256,SOURCE_SIZE} from './patch.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url)),ROOT=path.resolve(HERE,'../..');
const REVIEW='artifacts/research/vmde/startup-context/api-frame-review.json';
const REVIEW_SHA256='2926b9795e54ae17bbdffa80d6a81b7d50fe59a10f99bef8ad02217a9edcefdf';
const DEPENDENCIES=[
 ['dist/src/pe.js','fd8b62d43aff61f71a0fb3dcf13f8fc0c80ed95e354f70731d422854aaabbf08'],
 ['artifacts/research/vmde/native-kernel/io.mjs','e879bb7f99ca62c369b972fba277761d44dcbc92e6134914cc49f08a1c1708ce'],
 ['tools/startup-rebuild/patch.mjs',null],['tools/startup-rebuild/build.mjs',null]
];
const metadata=row=>({path:row.path,size_bytes:row.size_bytes,sha256:row.sha256});
const errorRecord=error=>({code:typeof error?.code==='string'?error.code:'STARTUP_REBUILD_FAILED',message:String(error?.message??error).replaceAll('\0','?').slice(0,2048)});
function requireValue(condition,message){if(!condition)throw new Error(message);}

function parseArguments(args){
 requireValue(Array.isArray(args)&&args.length>=2&&args.length<=8&&args.length%2===0,'Expected exactly --input ABSOLUTE_PATH --out NEW_ABSOLUTE_DIRECTORY');
 const result={};
 for(let i=0;i<args.length;i+=2){const key=args[i];requireValue(key==='--input'||key==='--out','Unknown option: '+key);requireValue(result[key]===undefined,'Repeated option: '+key);requireValue(typeof args[i+1]==='string'&&args[i+1].length>0,'Missing option value');result[key]=args[i+1];}
 requireValue(result['--input']!==undefined&&result['--out']!==undefined,'Both input and out options are required');return {input:result['--input'],out:result['--out']};
}

function validateReview(row){
 requireValue(row.schema_version===1&&row.status==='reviewed_observations_consistent','Pinned API frame review schema/status differ');
 const layout=row.conditional_frame_layout;
 requireValue(layout.helper_sha256==='dc2d38b7225847dfeae3bcfc949f506480796a8284dc8e45ae9d789986f05af2','Review helper identity differs');
 requireValue(layout.observed_tuple['EBP-0x18']==='0x19fe68'&&layout.static_scope_candidate.va==='0x8e02b8','Conditional frame evidence differs');
 for(const index of [50,51]){
  const event=row.selected_events.find(item=>item.event_index===index);
  requireValue(event&&event.event.context.ebp==='0x19fef8','Observed API frame base differs');
  requireValue(event.frame_dwords.some(item=>item.offset==='-0x20'&&item.value==='0x0'),'Observed quote-state is not zero');
 }
 return {path:REVIEW,sha256:REVIEW_SHA256,observed_thread:36480,ebp:'0x19fef8',saved_sp:'0x19fe68',
  allocation_derivation:'(0x19fef8 - 0x19fe68) - 0x1c = 0x74, conditional on the exact helper and no later saved-SP overwrite',
  original_prefix_restored:false,oep_identified:false,runnable_verified:false};
}

/** New-directory file transaction only. It never loads, spawns or emulates a PE. */
export async function buildCompatibility({input,out}){
 const receipt={schema_version:1,kind:'experimental_compatibility_startup_build',status:'failed',error:null,
  started_utc:new Date().toISOString(),target_execution:'not_run',cpu_emulation_executed:false,
  original_prefix_restored:false,oep_identified:false,runnable_verified:false,inputs:[],outputs:[],inputs_unchanged:null};
 let destination=null,created=false;const registered=[];
 const fail=error=>{receipt.status='failed';receipt.error??=errorRecord(error);};
 try{
  const sourcePath=absolute(input);destination=await absent(out);
  const source=await readStable(sourcePath,16*1024*1024);
  registered.push(source);receipt.source=metadata(source);
  requireValue(source.sha256===SOURCE_SHA256&&source.size_bytes===SOURCE_SIZE,'Fixed source identity mismatch');
  const patched=patchCompatibilityStartup(source.bytes);
  receipt.patches=patched.patches;receipt.import_resolution=patched.import_resolution;receipt.assumptions=patched.assumptions;receipt.validation=patched.validation;
  const review=await readStable(path.join(ROOT,REVIEW),1024*1024);requireValue(review.sha256===REVIEW_SHA256,'Pinned API frame review identity differs');
  registered.push(review);receipt.frame_evidence=validateReview(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(review.bytes)));
  for(const [relative,expected] of DEPENDENCIES){const row=await readStable(path.join(ROOT,relative),1024*1024);requireValue(expected===null||row.sha256===expected,'Source dependency identity differs: '+relative);registered.push(row);}
  receipt.inputs=registered.map(metadata);
  // All source, instruction, import and output-path checks precede mkdir.
  await newDir(destination);created=true;
  const candidate=path.join(destination,'candidate.exe');receipt.outputs.push({file:'candidate.exe',path:candidate,state:'write_started',size_bytes:null,sha256:null});
  const written=await writeNew(candidate,Buffer.from(patched.bytes));receipt.outputs[0]={file:'candidate.exe',...metadata(written),state:'generated'};
  receipt.candidate_sha256=written.sha256;receipt.status='completed';
 }catch(error){fail(error);}
 finally{
  receipt.inputs=registered.map(metadata);
  receipt.inputs_unchanged=true;
  for(const original of registered){
   try{const current=await readStable(original.path,Math.max(original.size_bytes,1));requireValue(current.sha256===original.sha256&&current.size_bytes===original.size_bytes,'Registered source changed after preflight: '+original.path);}
   catch(error){receipt.inputs_unchanged=false;fail(error);}
  }
  if(created&&receipt.outputs[0]?.state==='write_started'){
   try{const observed=await readStable(receipt.outputs[0].path,16*1024*1024);receipt.outputs[0]={file:'candidate.exe',...metadata(observed),state:'unverified_partial'};}
   catch(error){receipt.outputs[0].observation_error=errorRecord(error);}
  }
  receipt.ended_utc=new Date().toISOString();
  if(created){
   try{const saved=await writeNew(path.join(destination,'receipt.json'),jsonBytes(receipt));receipt.receipt_file=metadata(saved);}
   catch(error){receipt.receipt_write_error=errorRecord(error);fail(error);}
  }
 }
 return receipt;
}

export async function main(args=process.argv.slice(2)){
 let result;
 try{result=await buildCompatibility(parseArguments(args));}
 catch(error){result={schema_version:1,kind:'experimental_compatibility_startup_build',status:'failed',error:errorRecord(error),target_execution:'not_run',cpu_emulation_executed:false,original_prefix_restored:false,oep_identified:false,runnable_verified:false,outputs:[]};}
 process.stdout.write(JSON.stringify(result)+'\n','utf8');return result.status==='completed'?0:1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))process.exitCode=await main();
