import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const node=process.platform==='win32'?path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe'):process.execPath;
const target=path.join(root,'artifacts/ida-mcp/runtime/vmde-window-00498000-source/vmde-window-00498000.exe');
const out=path.join(root,'artifacts/ida-mcp/integration');
const casePath=path.join(root,'cases','ida-public-mcp-'+Date.now());
await mkdir(out,{recursive:true});
const client=new Client({name:'wirefit-ida-acceptance',version:'1.0.0'});
const transport=new StdioClientTransport({command:node,args:[path.join(root,'dist/src/mcp.js'),'--case',casePath,'--create'],stderr:'pipe'});
let stderr='';transport.stderr?.on('data',bytes=>{if(stderr.length<65536)stderr+=bytes.toString('utf8');});
async function call(name,args){
 const reply=await client.callTool({name:'wirefit_'+name,arguments:args},undefined,{timeout:15000});
 if(reply.isError)throw new Error(JSON.stringify(reply.structuredContent));
 return reply.structuredContent;
}
const receipt={schema_version:1,started_at:new Date().toISOString(),case:casePath,target,target_execution:'not_run',status:'failed'};
try{
 await client.connect(transport);
 const catalog=await client.listTools();receipt.tools=catalog.tools.map(tool=>tool.name);
 const queries=JSON.parse(await readFile(path.join(root,'.local/ida-smoke-queries.json'),'utf8'));
 const job=await call('analyze_ida',{file:target,queries,timeout_ms:60000});receipt.job_id=job.job_id;
 const deadline=Date.now()+75000;let terminal;
 while(Date.now()<deadline){
  const current=await call('get_job',{job_id:job.job_id});
  if(['completed','failed','cancelled','interrupted'].includes(current.status)){terminal=current;break;}
  await new Promise(resolve=>setTimeout(resolve,100));
 }
 if(!terminal?.result_id)throw new Error('IDA public MCP did not produce a terminal result');
 receipt.job=terminal;
 const report=await call('get_report',{result_id:terminal.result_id});receipt.result=report.data;
 if(terminal.status!=='completed'||receipt.result?.status!=='completed'||receipt.result.queries.length!==7||receipt.result.cleanup?.process_closed!==true||receipt.result.database?.identity_verified!==true)throw new Error('IDA public MCP acceptance did not satisfy its evidence/cleanup assertions');
 const exported=await call('export_report',{result_id:terminal.result_id,out:path.join(out,'public-mcp-export-'+Date.now())});
 receipt.export=exported;receipt.status='passed';
}catch(error){receipt.error={message:String(error?.message??error)};process.exitCode=1;}
finally{
 if(receipt.job_id&&!receipt.job){
  try{
   await call('cancel_job',{job_id:receipt.job_id});
   const deadline=Date.now()+10000;
   while(Date.now()<deadline){const state=await call('get_job',{job_id:receipt.job_id});if(['completed','failed','cancelled','interrupted'].includes(state.status)){receipt.job=state;break;}await new Promise(resolve=>setTimeout(resolve,100));}
  }catch(error){receipt.cleanup_error=String(error?.message??error);}
 }
 try{await client.close();}catch(error){receipt.status='failed';receipt.cleanup_error=String(error?.message??error);process.exitCode=1;}
 receipt.finished_at=new Date().toISOString();receipt.stderr=stderr;
 await writeFile(path.join(out,'public-mcp.json'),JSON.stringify(receipt,null,2)+'\n','utf8');
 process.stdout.write(JSON.stringify({status:receipt.status,case:casePath,tools:receipt.tools?.length,job_id:receipt.job_id,result_id:receipt.job?.result_id,queries:receipt.result?.queries?.map(item=>({kind:item.query.kind,status:item.status})),cleanup:receipt.result?.cleanup,error:receipt.error,receipt:path.join(out,'public-mcp.json')})+'\n','utf8');
}
