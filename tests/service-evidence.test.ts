import {describe,it,expect} from 'vitest';
import {mkdtemp,rm,writeFile,readFile,open,mkdir,symlink,readdir} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {WirefitService} from '../src/service.js';
import {rootDir,sha256} from '../src/shared.js';
import {createEvidence} from '../vendor/rea/src/domain/evidence.js';
import {createEvidenceBundle} from '../vendor/rea/src/domain/evidenceBundle.js';

describe('service Evidence boundary and retained provenance',()=>{
 it.each([
  ['malformed JSON',Buffer.from('{"incomplete":','utf8'),'INVALID_REA_JSON'],
  ['invalid UTF-8',Buffer.from([0xc3,0x28]),'INVALID_REA_UTF8'],
 ] as const)('retains %s as a discoverable non-liftable byte attachment',async(_name,bytes,code)=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-service-evidence-'));const service=await WirefitService.create(path.join(root,'case'));
  try{
   const file=path.join(root,'invalid.json');await writeFile(file,bytes);
   const imported=await service.importEvidence(file);
   expect(imported.status).toBe('attachment_only');expect(imported.record_ids).toEqual([]);
   expect(imported.diagnostics.some(diagnostic=>diagnostic.code===code)).toBe(true);
   const attachment=await service.store.getObject<any>('evidence',imported.bundle_id);
   expect(attachment.status).toBe('attachment_only');
   expect(await service.store.readArtifact(attachment.bundle_artifact)).toEqual(bytes);
   expect(attachment.bundle_artifact.sha256).toBe(sha256(bytes));
   expect(attachment.bundle_artifact.media_type).toBe('application/octet-stream');
  }finally{await service.close();await rm(root,{recursive:true,force:true});}
 });
 it('rejects an oversized Evidence file before copying it into the case',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-service-large-'));const service=await WirefitService.create(path.join(root,'case'));
  try{
   const file=path.join(root,'oversized.json');const handle=await open(file,'w');try{await handle.truncate(64*1024*1024+1);}finally{await handle.close();}
   await expect(service.importEvidence(file)).rejects.toMatchObject({code:'RESOURCE_LIMIT'});
   expect(await service.store.listObjects('evidence')).toEqual([]);
   expect(await readdir(path.join(root,'case','artifacts')).catch(()=>[])).toEqual([]);
  }finally{await service.close();await rm(root,{recursive:true,force:true});}
 });
 it('keeps the computed SSA source map and original bundle reachable from an immutable lifted model',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-service-lift-'));const service=await WirefitService.create(path.join(root,'case'));
  try{
   const variable={kind:'register',size_bytes:8,location:'register:0x0',constant_hex:null};
   // Synthetic boundary record using the real pinned producer schema; no Ghidra run.
   const record=createEvidence({path:'/synthetic/fixture',sha256:'e'.repeat(64),format:'elf',architecture:'x86_64'},{id:'ghidra',name:'Ghidra',version:'12.1.4'}, {operation:'analyze_function',parameters:{},result:{native_value_flow:{available:true,provenance:'ghidra-high-pcode',operations:[{id:'a',address:'0x401000',sequence:0,opcode:'INT_ADD',is_dead:false,block_membership:'member',inputs:[variable,{kind:'constant',size_bytes:8,location:null,constant_hex:'1'}],output:variable}],def_use:[],parameters:[{ordinal:0,name:'x',data_type:'uint64_t'}],parameter_uses:[{ordinal:0,use:'a',input_index:0}],effects:[],truncated:false,omitted_operations_lower_bound:0,known_omitted_inputs:0,known_omitted_edges:0,limitations:['Synthetic test record.']}}});
   const file=path.join(root,'bundle.json');await writeFile(file,JSON.stringify(createEvidenceBundle([record])),'utf8');
   const imported=await service.importEvidence(file);const lifted=await service.liftModel(imported.record_ids[0]!,'a');
   const model=await service.store.getObject<any>('models',lifted.model_id);
   expect(model.provenance.source_artifacts.map((ref:any)=>ref.sha256)).toEqual([imported.artifact.sha256,lifted.source_map.sha256]);
   const sourceMap=JSON.parse((await service.store.readArtifact(lifted.source_map)).toString('utf8'));
   expect(sourceMap.sourceMap.some((entry:any)=>entry.operation_id==='a'&&entry.role==='output')).toBe(true);
   expect(lifted.target_replay_eligible).toBe(false);
   expect(model.provenance.source_ref.bundle_sha256).toBe(imported.artifact.sha256);
  }finally{await service.close();await rm(root,{recursive:true,force:true});}
 });
 it('rejects an acquisition Evidence junction before starting a REA process or creating an external directory',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-service-junction-'));const service=await WirefitService.create(path.join(root,'case'));
  try{
   const external=path.join(root,'external');await mkdir(external);
   await symlink(external,path.join(root,'case','evidence'),process.platform==='win32'?'junction':'dir');
   const state=await service.jobs.wait((await service.acquireEvidence({command:'wirefit-command-that-must-not-start'})).job_id);
   expect(state.status).toBe('failed');expect(state.error?.code).toBe('ARTIFACT_PATH_INVALID');
   expect(await readdir(external)).toEqual([]);
  }finally{await service.close();await rm(root,{recursive:true,force:true});}
 });
 it('keeps acquisition reports bounded while preserving the full MCP schemas and replies as an artifact',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'wirefit-service-catalog-'));const service=await WirefitService.create(path.join(root,'case'));
  try{
   const server=path.join(root,'synthetic-large-catalog.mjs');
   const source=`// Synthetic protocol fixture; no target is executed.
import {McpServer} from ${JSON.stringify(pathToFileURL(path.join(rootDir,'node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js')).href)};
import {StdioServerTransport} from ${JSON.stringify(pathToFileURL(path.join(rootDir,'node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js')).href)};
import {z} from ${JSON.stringify(pathToFileURL(path.join(rootDir,'node_modules/zod/index.js')).href)};
import {readFile,writeFile} from 'node:fs/promises';
const server=new McpServer({name:'synthetic-large-catalog',version:'6.7.0'});
const ok=value=>({structuredContent:value,content:[{type:'text',text:JSON.stringify(value)}],_meta:{provenance:{untrusted_content:true,source:'analysis_target'}}});
for(let i=0;i<24;i++)server.registerTool('padding_'+i,{description:'large synthetic catalog '.repeat(3000),inputSchema:{}},async()=>ok({synthetic:true}));
server.registerTool('binary_session',{inputSchema:{expected_package_version:z.string().optional(),expected_catalog_digest:z.string().optional()}},async()=>ok({result:{server_identity:{package:{name:'rea-agents',version:'6.7.0'},catalog:{digests:{combined_sha256:'96d8f6e6ea1b1ba13557216624a3461c738729d53c79b4b0100d1f3a3a32441c'}}}}}));
server.registerTool('export_evidence_bundle',{inputSchema:{path:z.string(),overwrite:z.boolean()}},async args=>{await writeFile(args.path,await readFile(${JSON.stringify(path.join(rootDir,'artifacts/rea/real-js-bundle.json'))}),{flag:'wx'});return ok({path:args.path});});
server.registerTool('close_binary',{inputSchema:{}},async()=>ok({closed:true}));
await server.connect(new StdioServerTransport());
`;
   await writeFile(server,source,'utf8');
   const state=await service.jobs.wait((await service.acquireEvidence({command:process.execPath,args:[server],timeoutMs:10000})).job_id);
   expect(state.status).toBe('completed');const compact=await service.getResult(state.result_id!) as any;
   expect(compact.tool_count).toBe(27);expect(compact.tools).toBeUndefined();expect(compact.replies).toBeUndefined();
   expect(Buffer.byteLength(JSON.stringify(compact),'utf8')).toBeLessThan(65536);
   const bytes=await service.store.readArtifact(compact.raw_artifact);expect(bytes.length).toBeGreaterThan(1048576);
   const raw=JSON.parse(bytes.toString('utf8'));expect(raw.tools).toHaveLength(27);expect(raw.replies.length).toBeGreaterThan(0);
   expect(raw.replies[0].reply.metadata.provenance.untrusted_content).toBe(true);
   expect((await service.getReport(state.result_id!)).data).toEqual(compact);
   expect(compact.saved.record_ids).toHaveLength(1);
  }finally{await service.close();await rm(root,{recursive:true,force:true});}
 },15000);
});
