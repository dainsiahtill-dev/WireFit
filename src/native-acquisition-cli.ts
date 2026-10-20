import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {performance} from 'node:perf_hooks';

/** Fixed public CLI owner with a narrow, in-process cancellation bridge. */
export async function runAcquisitionCli():Promise<void>{
 let pending=false,delivered=false,finished=false;
 let deadline=0,poll:NodeJS.Timeout|undefined;
 const clearPoll=()=>{if(poll!==undefined){clearTimeout(poll);poll=undefined;}};
 const deliver=()=>{
  clearPoll();
  if(finished||!pending||delivered)return;
  if(process.listenerCount('SIGTERM')>0){
   pending=false;delivered=true;process.emit('SIGTERM');return;
  }
  if(performance.now()<deadline){poll=setTimeout(deliver,10);poll.unref();}
 };
 const cancel=(message:unknown)=>{
  if(message===null||typeof message!=='object'||Array.isArray(message)||
     Object.keys(message).length!==1||!Object.hasOwn(message,'type')||
     (message as Record<string,unknown>).type!=='wirefit_cancel'||finished||delivered)return;
  if(!pending){pending=true;deadline=performance.now()+15000;}
  deliver();
 };
 // Register before importing CLI dependencies so an early IPC request is sticky.
 process.on('message',cancel);
 try{
  // argv[1] remains this bridge: the CLI module's direct-run guard is false,
  // while argv.slice(2) remains the caller's actual public command arguments.
  const {runCli}=await import('./cli.js');
  await runCli();
 }finally{
  finished=true;clearPoll();process.removeListener('message',cancel);
  if(process.connected)process.disconnect();
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)await runAcquisitionCli();
