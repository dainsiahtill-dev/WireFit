import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {mkdir,lstat,realpath,writeFile,readFile,rename,unlink} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {rootDir} from '../shared.js';
import {startWorkbench,type WorkbenchServer} from './server.js';
import {HttpError,requireValue} from './http.js';

const help='WireFit 可视化工作台\n\n  wirefit web [--port 4318]\n  wirefit web --stop\n\n默认地址 http://127.0.0.1:4318；Ctrl+C 安全关闭任务与服务。\n';
export function webOptions(argv:string[]){
 let port=4318,stop=false,showHelp=false;const seen=new Set<string>();
 for(let i=0;i<argv.length;i++){const key=argv[i]!;requireValue(!seen.has(key),400,'WEB_BAD_REQUEST','Duplicate option');seen.add(key);
  if(key==='--help'||key==='-h')showHelp=true;else if(key==='--stop')stop=true;else if(key==='--port'){const value=argv[++i];requireValue(value!==undefined&&/^[1-9][0-9]{0,4}$/.test(value)&&Number(value)<=65535,400,'WEB_BAD_REQUEST','Port must be 1..65535');port=Number(value);}else throw new HttpError(400,'WEB_BAD_REQUEST','Unknown web option: '+key);
 }
 return {port,stop,showHelp};
}
async function stateDirectory(){
 let current=rootDir;for(const part of ['.local','workbench']){current=path.join(current,part);await mkdir(current).catch(error=>{if(error.code!=='EEXIST')throw error;});const info=await lstat(current);requireValue(info.isDirectory()&&!info.isSymbolicLink(),400,'WEB_STATE_INVALID','Workbench state directory is not ordinary');const actual=await realpath(current);requireValue(actual.toLowerCase()===current.toLowerCase(),400,'WEB_STATE_INVALID','Workbench state directory is aliased');}return current;
}
export async function runWeb(argv:string[]=process.argv.slice(2)):Promise<number>{
 const options=webOptions(argv);if(options.showHelp){process.stdout.write(help,'utf8');return 0;}
 const directory=await stateDirectory(),stateFile=path.join(directory,`server-${options.port}.json`);
 if(options.stop){
  const state=JSON.parse(await readFile(stateFile,'utf8')) as {url:string;pid:number;instance_id:string};
  requireValue(state.url===`http://127.0.0.1:${options.port}`&&Number.isSafeInteger(state.pid)&&typeof state.instance_id==='string',400,'WEB_STATE_INVALID','Saved server identity is invalid');
  const response=await fetch(state.url+'/api/bootstrap',{signal:AbortSignal.timeout(10000)});const bootstrap=await response.json() as {data:{product:string;pid:number;instance_id:string;token:string}};
  requireValue(response.ok&&bootstrap.data?.product==='WireFit'&&bootstrap.data.pid===state.pid&&bootstrap.data.instance_id===state.instance_id,409,'WEB_STATE_INVALID','Live server differs from the saved owned instance');
  const stopped=await fetch(state.url+'/api/shutdown',{method:'POST',headers:{'Content-Type':'application/json',Origin:state.url,'X-Wirefit-Token':bootstrap.data.token},body:'{}',signal:AbortSignal.timeout(10000)});
  requireValue(stopped.ok,500,'WEB_CLOSE_FAILED','Server did not accept shutdown');process.stdout.write(JSON.stringify({status:'shutdown_requested',url:state.url})+'\n','utf8');return 0;
 }
 let app:WorkbenchServer|undefined;let temp:string|undefined;
 try{
  app=await startWorkbench({root:rootDir,port:options.port});
  try{const info=await lstat(stateFile);requireValue(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1,400,'WEB_STATE_INVALID','State file is not ordinary');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  temp=stateFile+'.'+randomUUID()+'.tmp';await writeFile(temp,JSON.stringify({schema_version:1,product:'WireFit',pid:process.pid,url:app.url,instance_id:app.instanceId,started_at:new Date().toISOString()},null,2)+'\n',{encoding:'utf8',flag:'wx'});await rename(temp,stateFile);temp=undefined;
  process.stdout.write(JSON.stringify({product:'WireFit',status:'listening',url:app.url,pid:process.pid,state_file:stateFile})+'\n','utf8');
  await new Promise<void>((resolve,reject)=>{
   const stop=()=>{void app!.close().then(resolve,reject);};const closed=()=>resolve();
   process.once('SIGINT',stop);process.once('SIGTERM',stop);app!.server.once('close',closed);
   app!.server.once('close',()=>{process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);});
  });
  await app.close();return 0;
 }finally{
  if(app){await app.close();try{const state=JSON.parse(await readFile(stateFile,'utf8'));if(state.instance_id===app.instanceId)await unlink(stateFile);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')process.stderr.write(JSON.stringify({error:{code:'WEB_STATE_CLEANUP',message:String(error)}})+'\n','utf8');}}
  if(temp)await unlink(temp).catch(()=>undefined);
 }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 runWeb().then(code=>{process.exitCode=code;},error=>{process.stderr.write(JSON.stringify({error:{code:error?.code??'WEB_START_FAILED',message:String(error?.message??error)}})+'\n','utf8');process.exitCode=1;});
}
