import {spawn,spawnSync,type ChildProcess} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {assert,WirefitError} from './shared.js';
export interface ProcessOptions {cwd?:string;env?:NodeJS.ProcessEnv;input?:string;timeout_ms?:number;max_stdout_bytes?:number;max_stderr_bytes?:number;signal?:AbortSignal;cancel_ipc?:{message:Record<string,unknown>;grace_ms:number}}
export interface ProcessResult {stdout:string;stderr:string;code:number|null;signal:string|null;duration_ms:number;stderr_truncated:boolean;pid:number}
function cancellationOptions(value:ProcessOptions['cancel_ipc']):ProcessOptions['cancel_ipc'] {
 if(value===undefined)return;
 assert(value!==null&&typeof value==='object'&&!Array.isArray(value)&&Reflect.ownKeys(value).length===2,'PROCESS_INVALID','Invalid IPC cancellation fields');
 const messageField=Object.getOwnPropertyDescriptor(value,'message'),graceField=Object.getOwnPropertyDescriptor(value,'grace_ms');
 assert(messageField&&'value'in messageField&&messageField.enumerable&&graceField&&'value'in graceField&&graceField.enumerable,'PROCESS_INVALID','IPC cancellation fields must be plain data');
 const message:unknown=messageField.value,graceMs:unknown=graceField.value;
 assert(typeof graceMs==='number'&&Number.isInteger(graceMs)&&graceMs>=1&&graceMs<=15000,'PROCESS_INVALID','IPC cancellation grace must be 1..15000 ms');
 assert(message!==null&&typeof message==='object'&&!Array.isArray(message),'PROCESS_INVALID','IPC cancellation message must be a JSON object');
 const ancestors=new Set<object>();let nodes=0;
 const clone=(input:unknown,depth:number):unknown=>{
  assert(depth<=64&&++nodes<=8192,'PROCESS_INVALID','IPC cancellation JSON is excessive');
  if(input===null||typeof input==='string'||typeof input==='boolean')return input;
  if(typeof input==='number'){assert(Number.isFinite(input),'PROCESS_INVALID','IPC cancellation JSON must contain finite numbers');return input;}
  assert(typeof input==='object'&&!ancestors.has(input),'PROCESS_INVALID','IPC cancellation message must contain only acyclic JSON values');
  assert(Array.isArray(input)||Object.getPrototypeOf(input)===Object.prototype||Object.getPrototypeOf(input)===null,'PROCESS_INVALID','IPC cancellation JSON must contain plain objects');
  ancestors.add(input);
  try{
   if(Array.isArray(input)){
    assert(input.length<=4096&&Reflect.ownKeys(input).length===input.length+1,'PROCESS_INVALID','IPC cancellation arrays must be bounded and dense');
    return Array.from({length:input.length},(_,index)=>{
     const descriptor=Object.getOwnPropertyDescriptor(input,String(index));
     assert(descriptor&&'value'in descriptor,'PROCESS_INVALID','IPC cancellation arrays cannot contain accessors or holes');
     return clone(descriptor.value,depth+1);
    });
   }
   const output:Record<string,unknown>=Object.create(null);
   for(const key of Reflect.ownKeys(input)){
    const descriptor=Object.getOwnPropertyDescriptor(input,key);
    assert(typeof key==='string'&&descriptor&&descriptor.enumerable&&'value'in descriptor,'PROCESS_INVALID','IPC cancellation JSON cannot contain symbols or accessors');
    output[key]=clone(descriptor.value,depth+1);
   }
   return output;
  }finally{ancestors.delete(input);}
 };
 try{
  const encoded=JSON.stringify(clone(message,0));
  assert(Buffer.byteLength(encoded,'utf8')<=4096,'PROCESS_INVALID','IPC cancellation message exceeds 4096 UTF-8 bytes');
  return {message:JSON.parse(encoded) as Record<string,unknown>,grace_ms:graceMs};
 }catch(error){if(error instanceof WirefitError)throw error;throw new WirefitError('PROCESS_INVALID','Invalid IPC cancellation JSON');}
}
function terminateOwned(child:ChildProcess):void{
 if(child.exitCode!==null||child.signalCode!==null||child.pid===undefined)return;
 if(process.platform==='win32'){
  spawnSync('taskkill.exe',['/PID',String(child.pid),'/T','/F'],{windowsHide:true,stdio:'ignore',timeout:3000});
  child.kill('SIGKILL');
 }else{
  try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}
 }
}
export async function runProcess(command:string,args:string[],options:ProcessOptions={}):Promise<ProcessResult>{
 assert(typeof command==='string'&&command.length>0&&Array.isArray(args)&&args.every(arg=>typeof arg==='string'),'PROCESS_INVALID','Command and argv must be explicit strings');
 const cancellation=cancellationOptions(options.cancel_ipc);
 const timeout=options.timeout_ms??120000;
 assert(Number.isInteger(timeout)&&timeout>0&&timeout<=86400000,'PROCESS_INVALID','Invalid worker timeout');
 if(options.signal?.aborted)throw new WirefitError('CANCELLED','Worker cancelled before start');
 return new Promise((resolve,reject)=>{
  const started=performance.now();
  const stdio:['pipe','pipe','pipe']|['pipe','pipe','pipe','ipc']=cancellation?['pipe','pipe','pipe','ipc']:['pipe','pipe','pipe'];
  const child=spawn(command,args,{cwd:options.cwd,env:options.env,shell:false,windowsHide:true,detached:process.platform!=='win32',stdio});
  const stdout:Buffer[]=[];const stderr:Buffer[]=[];
  let outSize=0;let errSize=0;let truncated=false;let failure:Error|undefined;let settled=false;
  let timer:NodeJS.Timeout|undefined,grace:NodeJS.Timeout|undefined;
  let forced=false,cancelMode:'ipc_requested'|'forced'|undefined;
  const clearGrace=()=>{if(grace!==undefined){clearTimeout(grace);grace=undefined;}};
  const force=()=>{
   clearGrace();
   if(settled||forced||child.exitCode!==null||child.signalCode!==null||child.pid===undefined)return;
   forced=true;if(cancellation)cancelMode='forced';terminateOwned(child);
  };
  const fail=(error:Error,requestCancellation=false)=>{
   if(settled)return;
   const first=failure===undefined;if(first)failure=error;
   if(!requestCancellation||!cancellation){force();return;}
   // Subsequent abort/timeout notifications never replace or shorten the first
   // request. Output limits and startup/channel failures can still force stop.
   if(!first)return;
   if(child.exitCode!==null||child.signalCode!==null)return;
   if(!child.connected||typeof child.send!=='function'){force();return;}
   cancelMode='ipc_requested';
   try{
    child.send(cancellation.message,error=>{if(error)force();});
    if(!settled&&!forced)grace=setTimeout(force,cancellation.grace_ms);
   }catch{force();}
  };
  const abort=()=>fail(new WirefitError('CANCELLED','Worker cancelled'),true);
  child.stdout!.on('data',(data:Buffer)=>{
   outSize+=data.byteLength;
   if(outSize>(options.max_stdout_bytes??1048576)){fail(new WirefitError('RESOURCE_LIMIT','Worker stdout size limit exceeded'));return;}
   stdout.push(data);
  });
  child.stderr!.on('data',(data:Buffer)=>{
   const remaining=(options.max_stderr_bytes??1048576)-errSize;
   if(remaining>0){const part=data.subarray(0,remaining);stderr.push(part);errSize+=part.byteLength;}
   if(data.byteLength>remaining)truncated=true;
  });
  child.on('error',error=>fail(new WirefitError('PROCESS_START_FAILED','Could not start worker: '+error.message)));
  child.on('close',(code,signal)=>{
   if(settled)return;settled=true;if(timer!==undefined)clearTimeout(timer);clearGrace();options.signal?.removeEventListener('abort',abort);
   if(failure){if(failure instanceof WirefitError)failure.details={stdout:Buffer.concat(stdout).toString('utf8'),stderr:Buffer.concat(stderr).toString('utf8'),code,signal,duration_ms:performance.now()-started,stderr_truncated:truncated,pid:child.pid??0,cleanup:'closed',...(cancelMode?{cancel_mode:cancelMode}:{})};reject(failure);return;}
   try{
    const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(stdout));
    resolve({stdout:text,stderr:Buffer.concat(stderr).toString('utf8'),code,signal,duration_ms:performance.now()-started,stderr_truncated:truncated,pid:child.pid??0});
   }catch{reject(new WirefitError('PROTOCOL_ERROR','Worker stdout is not valid UTF-8',{stdout:Buffer.concat(stdout).toString('utf8'),stderr:Buffer.concat(stderr).toString('utf8'),code,signal,duration_ms:performance.now()-started,stderr_truncated:truncated,pid:child.pid??0,cleanup:'closed'}));}
  });
  child.stdin!.on('error',()=>undefined);
  timer=setTimeout(()=>fail(new WirefitError('TIMEOUT','Worker timeout exceeded'),true),timeout);
  options.signal?.addEventListener('abort',abort,{once:true});
  if(options.signal?.aborted)abort();
  child.stdin!.end(options.input??'','utf8');
 });
}
