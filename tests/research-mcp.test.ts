import {it,expect} from 'vitest';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {mkdtemp,rm} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';

const root=path.resolve('.'),
 local=path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe'),
 runtime=process.platform==='win32'&&existsSync(local)?local:process.execPath;

async function setup(){
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-research-mcp-'));
 const client=new Client({name:'wirefit-research-test',version:'1.0'});
 const transport=new StdioClientTransport({
  command:runtime,
  args:['--import','tsx',path.join(root,'src/mcp.ts'),'--case',path.join(dir,'case'),'--create'],
  stderr:'pipe',
 });
 await client.connect(transport);
 return {dir,client};
}

it('advertises nineteen tools including the two research tools',async()=>{
 const {dir,client}=await setup();
 try{
  const listed=await client.listTools();
  const names=listed.tools.map((tool)=>tool.name);
  expect(listed.tools).toHaveLength(19);
  expect(names).toContain('wirefit_research_directions');
  expect(names).toContain('wirefit_run_research_direction');
  const directions=listed.tools.find((tool)=>tool.name==='wirefit_research_directions');
  expect(directions?.annotations?.readOnlyHint).toBe(true);
  expect(directions?.annotations?.openWorldHint).toBeFalsy();
  const run=listed.tools.find((tool)=>tool.name==='wirefit_run_research_direction');
  expect(run?.annotations?.openWorldHint).toBe(true);
  const report=listed.tools.find((tool)=>tool.name==='wirefit_get_report');
  expect(JSON.stringify(report?.inputSchema)).toContain('audit');
 }finally{
  await client.close();
  await rm(dir,{recursive:true,force:true});
 }
},120000);

it('lists the seventeen directions and reads one specification',async()=>{
 const {dir,client}=await setup();
 try{
  const listed=await client.callTool({name:'wirefit_research_directions',arguments:{}});
  const payload=JSON.parse((listed.content as {text:string}[])[0]!.text) as {directions:{direction_id:string}[]};
  expect(payload.directions).toHaveLength(17);
  const one=await client.callTool({name:'wirefit_research_directions',arguments:{direction_id:'D07'}});
  const spec=JSON.parse((one.content as {text:string}[])[0]!.text) as {direction_id:string;claims:unknown[]};
  expect(spec.direction_id).toBe('D07');
  expect(spec.claims.length).toBeGreaterThan(0);
  const unknown=await client.callTool({name:'wirefit_research_directions',arguments:{direction_id:'D99'}});
  expect(unknown.isError).toBe(true);
 }finally{
  await client.close();
  await rm(dir,{recursive:true,force:true});
 }
},120000);
