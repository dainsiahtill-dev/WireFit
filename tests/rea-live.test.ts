import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { acquireEvidence, importPortableEvidence } from '../src/rea.js';

const runtime = path.resolve('.upstream/rea-runtime/node_modules/rea-agents/scripts/rea.mjs');
const temporary: string[] = [];
const syntheticServer = path.resolve('artifacts/rea/synthetic-lifecycle-server.mjs');
afterEach(async()=>{ for (const directory of temporary.splice(0)) await rm(directory,{recursive:true,force:true}); });

describe('REA actual captured portable fixture', () => {
  it('authenticates the real server-exported JavaScript Evidence offline', async()=>{
    const bytes = await readFile(path.resolve('artifacts/rea/real-js-bundle.json'),'utf8');
    const imported = importPortableEvidence(JSON.parse(bytes));
    expect(imported.status).toBe('supported');
    expect(imported.records).toHaveLength(1);
    expect(imported.records[0]?.operation).toBe('analyze_javascript_application');
  });
});

describe('REA synthetic MCP lifecycle failure and cancellation boundaries',()=>{
  it('rejects same-version live schema drift using the pinned catalog identity',async()=>{
    const directory = await mkdtemp(path.join(tmpdir(),'wirefit-rea-catalog-')); temporary.push(directory);
    const result = await acquireEvidence({command:process.execPath,args:[syntheticServer,path.join(directory,'events'),'wrong-catalog'],destination:path.join(directory,'bundle.json'),timeoutMs:5000});
    expect(result.status).toBe('failed');
    expect(result.diagnostics.some(diagnostic=>diagnostic.code==='UNSUPPORTED_REA_SERVER_IDENTITY')).toBe(true);
  },10000);
  it('marks incomplete provider cleanup as failed instead of completed',async()=>{
    const directory = await mkdtemp(path.join(tmpdir(),'wirefit-rea-cleanup-')); temporary.push(directory);
    const result = await acquireEvidence({command:process.execPath,args:[syntheticServer,path.join(directory,'events'),'fail-close'],destination:path.join(directory,'bundle.json'),timeoutMs:5000});
    expect(result.persisted).toBe(true);
    expect(result.cleanup.closed).toBe(false);
    expect(result.status).toBe('failed');
    expect(result.diagnostics.some(diagnostic=>diagnostic.code==='REA_CLEANUP_INCOMPLETE')).toBe(true);
  },10000);
  it('refreshes capability state after a rejected binding and saves recovery export',async()=>{
    const directory = await mkdtemp(path.join(tmpdir(),'wirefit-rea-binding-')); temporary.push(directory);
    const result = await acquireEvidence({command:process.execPath,args:[syntheticServer,path.join(directory,'events'),'fail-open'],target:process.execPath,destination:path.join(directory,'bundle.json'),timeoutMs:5000});
    expect(result.status).toBe('failed');
    expect(result.capabilities.after).not.toBeNull();
    expect(result.persisted).toBe(true);
    expect(result.cleanup.closed).toBe(true);
  },10000);
  it('uses a fresh bounded recovery request after cancelling active analysis',async()=>{
    const directory = await mkdtemp(path.join(tmpdir(),'wirefit-rea-cancel-')); temporary.push(directory);
    const eventPath = path.join(directory,'events');
    const controller = new AbortController();
    const request = acquireEvidence({command:process.execPath,args:[syntheticServer,eventPath,'cancel'],target:process.execPath,functionAddress:'test',destination:path.join(directory,'bundle.json'),timeoutMs:5000,recoveryTimeoutMs:2000,
      persist:async()=>{ await readFile(path.join(directory,'bundle.json'),'utf8'); },
    },controller.signal);
    const started=Date.now();
    while(Date.now()-started<4000){
      const events=await readFile(eventPath,'utf8').catch(()=> '');
      if(events.includes('analyzing'))break;
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    controller.abort();
    const result=await request;
    expect(result.status).toBe('cancelled');
    expect(result.persisted).toBe(true);
    expect(result.imported?.records).toHaveLength(1);
    expect((await readFile(eventPath,'utf8')).trim().split('\n').slice(-2)).toEqual(['export','close']);
  },10000);
});

describe.skipIf(!existsSync(runtime))('REA real installed public-entrypoint lifecycle', () => {
  it('persists an authenticated export before closing its owned session',async()=>{
    const directory = await mkdtemp(path.join(tmpdir(),'wirefit-rea-live-')); temporary.push(directory);
    let callbackRecords: number | undefined;
    const result = await acquireEvidence({command:process.execPath,args:[runtime,'--mcp'],destination:path.join(directory,'bundle.json'),timeoutMs:30000,
      persist:async(imported,bytes)=>{ callbackRecords=imported.records.length; expect(bytes.length).toBeGreaterThan(0); },
    });
    expect(result.status).toBe('completed');
    expect(result.persisted).toBe(true);
    expect(result.cleanup.closed).toBe(true);
    expect(callbackRecords).toBe(0);
    expect(result.tools.length).toBeGreaterThan(0);
    expect(result.replies.map(entry=>entry.name)).toEqual(['binary_session','binary_session','export_evidence_bundle','close_binary']);
    expect(importPortableEvidence(JSON.parse(await readFile(path.join(directory,'bundle.json'),'utf8'))).status).toBe('supported');
  },45000);
});
