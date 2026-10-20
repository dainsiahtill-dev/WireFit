import {lstat} from 'node:fs/promises';
import path from 'node:path';
import {assert} from '../shared.js';
import {submitBinaryInspection,submitBinaryUnpack,validateBinaryToolchain,type BinaryCommand,type BinaryToolchain} from '../binary-service.js';
import {submitBinaryTrace,type NativeTracePlan} from '../native-trace.js';
import type {WirefitService} from '../service.js';
import type {JobState} from '../jobs.js';
import type {WebProfile,WebTaskRequest} from './types.js';
import {jsonFile,noLinks} from './workspace-paths.js';
import {submitIdaAnalysis,loadIdaConfiguration} from '../ida/index.js';

interface SelectedProfile {description:WebProfile;binary?:BinaryToolchain;trace?:BinaryCommand}
const DEFAULT_PLAN:NativeTracePlan={duration_ms:3000,breakpoints_rva:[],ranges:[],api_hooks:[],max_events:128};
async function installed(command:BinaryCommand|undefined):Promise<boolean>{
 if(!command||!path.isAbsolute(command.command))return false;
 try{await noLinks(command.command);return (await lstat(command.command)).isFile();}catch{return false;}
}
export class WorkbenchActions {
 private constructor(private readonly root:string,private readonly selected:SelectedProfile[]){}
 static async open(root:string):Promise<WorkbenchActions>{
  const selected:SelectedProfile[]=[{description:{id:'pe-static',label:'PE 静态检查（不执行目标）',kind:'inspect',available:true}}];
  try{
   const binary=await jsonFile<BinaryToolchain>(path.join(root,'.local','binary-tools.x86.json'));validateBinaryToolchain(binary);
   if(await installed(binary.detector))selected.push({description:{id:'pe-die-x86',label:'PE + 已安装 DIE 检测',kind:'inspect',available:true},binary:{detector:binary.detector}});
   selected.push({description:{id:'unlicense-x86',label:'已安装 unlicense x86',kind:'unpack',available:await installed(binary.unpackers?.unlicense)},binary});
  }catch{selected.push({description:{id:'unlicense-x86',label:'unlicense x86（未安装）',kind:'unpack',available:false}});}
  try{
   const trace=await jsonFile<BinaryCommand>(path.join(root,'.local','native-trace.json'));
   validateBinaryToolchain({detector:trace});
   selected.push({description:{id:'native-trace',label:'本机原生观测（有界执行）',kind:'trace',available:await installed(trace)},trace});
  }catch{selected.push({description:{id:'native-trace',label:'本机原生观测（未安装）',kind:'trace',available:false}});}
  return new WorkbenchActions(root,selected);
 }
 profiles():WebProfile[]{return this.selected.map(item=>({...item.description}));}
 async submit(service:WirefitService,request:WebTaskRequest):Promise<JobState>{
  assert(request!==null&&typeof request==='object'&&!Array.isArray(request),'TASK_REQUEST_INVALID','Task must be an object');
  if(request.kind==='ida'){
   assert(Object.keys(request).every(key=>['kind','file','queries','timeout_ms'].includes(key)),'TASK_REQUEST_INVALID','IDA task has unsupported fields');
   const {kind:_,...analysis}=request;
   return submitIdaAnalysis(service,analysis,await loadIdaConfiguration(this.root));
  }
  if(request.kind==='experiment'){
   assert(Object.keys(request).every(key=>['kind','request'].includes(key)),'TASK_REQUEST_INVALID','Experiment task has unsupported fields');
   return service.submitExperiment(request.request);
  }
  assert(['inspect','trace','unpack'].includes(request.kind)&&Object.keys(request).every(key=>['kind','file','profileId','plan'].includes(key)),'TASK_REQUEST_INVALID','Task has unsupported kind or fields');
  assert(typeof request.file==='string'&&request.file.length>0&&request.file.length<=4096&&!request.file.includes('\0'),'TASK_REQUEST_INVALID','Input must be a bounded local filename');
  const selected=this.selected.find(item=>item.description.id===request.profileId&&item.description.kind===request.kind&&item.description.available);
  assert(selected,'PROFILE_UNAVAILABLE','Select an installed profile for this task');
  const file=path.resolve(this.root,request.file);await noLinks(file);
  if(request.kind==='inspect'){
   assert(request.plan===undefined,'TASK_REQUEST_INVALID','Static inspection does not take a trace plan');
   return submitBinaryInspection(service,{file,...(selected.binary?{toolchain:structuredClone(selected.binary)}:{}),timeout_ms:120000});
  }
  if(request.kind==='trace')return submitBinaryTrace(service,{file,tool:structuredClone(selected.trace!),plan:structuredClone((request.plan??DEFAULT_PLAN) as NativeTracePlan)});
  assert(request.plan===undefined,'TASK_REQUEST_INVALID','Unpacking does not take a trace plan');
  return submitBinaryUnpack(service,{file,backend:'unlicense',toolchain:structuredClone(selected.binary!),timeout_ms:240000,target_timeout_seconds:60});
 }
}
