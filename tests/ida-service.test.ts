import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { WirefitService } from '../src/service.js';
import { submitIdaAnalysis, type IdaConfiguration, type IdaAnalysisResult } from '../src/ida/index.js';
const roots: string[] = [];
const fixture = String.raw`
import readline from 'node:readline';import {readFileSync,writeFileSync} from 'node:fs';import {createHash} from 'node:crypto';
const input=process.argv[2],database=process.argv[3],mode=process.env.IDA_TEST_MODE;
const tools=['wirefit_identity','server_health','list_funcs','entity_query','type_query','decompile','disasm','basic_blocks','func_profile','xrefs_to','callees','get_bytes','ida_close','py_eval'].map(name=>({name,inputSchema:{type:'object',additionalProperties:true}}));
const send=(id,result)=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\n');
readline.createInterface({input:process.stdin}).on('line',line=>{const message=JSON.parse(line);if(message.id===undefined)return;
 if(message.method==='initialize'){send(message.id,{protocolVersion:'2024-11-05',capabilities:{tools:{}},serverInfo:{name:'IDA test protocol fixture',version:'9.3'}});return;}
 if(message.method==='tools/list'){send(message.id,{tools});return;}
 if(message.method!=='tools/call')return;
 const {name,arguments:args}=message.params;let result;
 if(name==='wirefit_identity')result={input_path:mode==='wrong-identity'?'C:/outside/user.exe':input,sha256:createHash('sha256').update(readFileSync(input)).digest('hex'),idb_path:mode==='unowned-database'?'C:/outside/existing.i64':database,imagebase:'0x140000000',version:'9.3',owned:mode!=='unowned-database',pid:process.pid,revision:mode==='wrong-provider'?'b'.repeat(40):'a'.repeat(40),analysis_completed:mode!=='incomplete'};
 else if(name==='ida_close')result={idb_closed:true,owned:true,pid:process.pid};
 else if(mode==='hang'){writeFileSync('query-ready','ready','utf8');setInterval(()=>{},1000);return;}
 else if(name==='server_health'){if(mode==='source-change')writeFileSync(process.env.IDA_TEST_ORIGINAL,Buffer.from([0xcc,0xc3]));result={healthy:true,version:'9.3'};}
 else if(name==='list_funcs')result=[{data:[{addr:'0x140001000',name:'main'}],next_offset:null}];
 else if(name==='entity_query')result=[{kind:'strings',data:[{addr:'0x140002000',string:'hello'}],next_offset:null}];
 else if(name==='type_query')result=[{data:[{name:'example_t',size:8}],next_offset:null}];
 else if(name==='decompile')result=mode==='decompile-error'?{addr:args.addr,code:null,error:'Hex-Rays unavailable'}:{addr:args.addr,code:'int main(void) { return 7; }',cursor:{done:true}};
 else if(name==='disasm')result={addr:args.addr,asm:{name:'main',lines:mode==='excessive-listing'?Array.from({length:501},()=>({addr:'0x140001000',instruction:'ret'})):[{addr:'0x140001000',instruction:'ret'}]},cursor:{done:true}};
 else if(name==='basic_blocks')result=[{addr:args.addrs,blocks:[{start:mode==='malformed-cfg'?'not-an-address':'0x140001000',end:'0x140001001',successors:[]}],cursor:{done:true}}];
 else if(name==='func_profile')result=[{data:[{name:'main',callers:[],callees:[]}],next_offset:null}];
 else if(name==='xrefs_to')result=[{addr:args.addrs,xrefs:[],more:false}];
 else if(name==='callees')result=[{addr:args.addrs,callees:[],more:false}];
 else if(name==='get_bytes'){
  if(mode==='tool-error'){send(message.id,{isError:true,content:[{type:'text',text:'cannot read bytes'}]});return;}
  result=[{addr:mode==='wrong-address'?'0x2000':args.regions.addr,data:mode==='invalid-bytes'?null:'0xc3'}];
 }
 else {send(message.id,{isError:true,content:[{type:'text',text:'forbidden tool'}]});return;}
 if(mode==='wide-number'&&name==='type_query'){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:message.id,result:{content:[],structuredContent:{result}}}).replace('"size":8','"size":18446744073709551615')+'\n');return;}
 const value=Array.isArray(result)?{result}:result;send(message.id,{content:[{type:'text',text:JSON.stringify(result)}],structuredContent:value,...(mode==='metadata-truncated'&&name==='server_health'?{_meta:{ida_mcp:{output_truncated:true}}}:{})});
});
`;
async function setup(mode = 'normal') {
  const root = await mkdtemp(path.join(tmpdir(), 'wirefit-ida-job-'));
  roots.push(root);
  const service = await WirefitService.create(path.join(root, 'case'));
  const file = path.join(root, 'source.bin');
  await writeFile(file, Buffer.from([0x90, 0xc3]));
  const script = path.join(root, 'fixture.mjs');
  await writeFile(script, fixture, 'utf8');
  const configuration: IdaConfiguration = {
    schema_version: 1,
    lifecycle: 'owned-stdio',
    command: process.execPath,
    args: [script, '{input}', '{database}'],
    env: { IDA_TEST_MODE: mode, IDA_TEST_ORIGINAL: file },
    provider: { version: '9.3', server: 'IDA test protocol fixture', revision: 'a'.repeat(40) },
  };
  return { root, service, file, configuration };
}
afterEach(async () => {
  for (const root of roots.splice(0)) {
    expect(path.resolve(root).startsWith(path.resolve(tmpdir()) + path.sep + 'wirefit-ida-job-')).toBe(true);
    await rm(root, { recursive: true, force: true });
  }
});
async function receipt(service: WirefitService, jobId: string) {
  const state = await service.jobs.wait(jobId);
  expect(state.result_id).toBeTruthy();
  return { state, result: (await service.getResult(state.result_id!)) as IdaAnalysisResult };
}
async function raw(service: WirefitService, result: IdaAnalysisResult) {
  return Promise.all(
    result.artifacts
      .filter((ref) => ref.media_type === 'application/json')
      .map(async (ref) => JSON.parse((await service.store.readArtifact(ref)).toString('utf8'))),
  );
}
describe('owned IDA evidence jobs', () => {
  it('marks upstream envelope-only truncation as partial evidence', async () => {
    const {service,file,configuration}=await setup('metadata-truncated');
    try {
      const {result}=await receipt(service,(await submitIdaAnalysis(service,{file,queries:[{kind:'overview'}]},configuration)).job_id);
      expect(result.status).toBe('partial');
      expect(result.queries[0]!.status).toBe('partial');
      expect(result.queries[0]!.data?.truncated).toBe(true);
    } finally {await service.close();}
  });
  it('rejects an unverified production receipt before creating a runnable job', async () => {
    const { service, file, configuration, root } = await setup();
    const probe = path.join(root, 'stale-probe.json');
    await writeFile(
      probe,
      JSON.stringify({
        status: 'completed',
        revision: configuration.provider.revision,
        configuration_sha256: '0'.repeat(64),
        native_initialized: true,
        mcp_handshake: true,
        identity_verified: true,
        fixture: { disassembly: true, decompilation: true },
      }),
      'utf8',
    );
    try {
      await expect(
        submitIdaAnalysis(
          service,
          { file, queries: [{ kind: 'overview' }] },
          { ...configuration, probe_receipt: probe },
        ),
      ).rejects.toThrow();
      expect(await service.store.listObjects('jobs')).toEqual([]);
    } finally {
      await service.close();
    }
  });
  it('copies input, verifies database identity and retains raw catalog and every reply', async () => {
    const { service, file, configuration } = await setup();
    try {
      const job = await submitIdaAnalysis(
        service,
        {
          file,
          queries: [
            { kind: 'overview' },
            { kind: 'functions', limit: 3 },
            { kind: 'strings' },
            { kind: 'function', address: '0x140001000' },
            { kind: 'xrefs', address: '0x140001000' },
            { kind: 'bytes', address: '0x140001000', size: 1 },
            { kind: 'types' },
          ],
        },
        configuration,
      );
      const { state, result } = await receipt(service, job.job_id);
      expect(state.status).toBe('completed');
      expect(result.status).toBe('completed');
      expect(result.database.identity_verified).toBe(true);
      expect(result.database.input_path).not.toBe(file);
      expect(result.source.sha256).toBe('36565ca5d2854ac584ac1356867f5c575d0f489442f8c8b4b8c391b2246ec1e5');
      expect(result.queries[3]!.data?.pseudocode).toBe('int main(void) { return 7; }');
      expect(result.queries[3]!.data?.disassembly).toEqual([{ addr: '0x140001000', instruction: 'ret' }]);
      expect(result.queries[3]!.data?.basic_blocks).toEqual({
        nodes: [{ id: '0x140001000', start: '0x140001000', end: '0x140001001', successors: [] }],
        edges: [],
      });
      expect(result.cleanup).toMatchObject({
        owned: true,
        idb_closed: true,
        process_closed: true,
        forced: false,
      });
      expect(result.validation).toEqual({
        source_unchanged: true,
        runnable_verified: false,
        whole_program_equivalence: false,
      });
      expect(await service.store.readArtifact(result.source.artifact)).toEqual(Buffer.from([0x90, 0xc3]));
      expect(result.tool_catalog_artifact).toBeTruthy();
      const evidence = await raw(service, result);
      expect(evidence.some((item) => item.tool === 'get_bytes' && item.arguments?.regions?.size === 1)).toBe(
        true,
      );
      expect(evidence.some((item) => item.tool === 'ida_close')).toBe(true);
      expect(evidence.some((item) => item.tool === 'py_eval')).toBe(false);
    } finally {
      await service.close();
    }
  });
  it('keeps other query results after tool-level errors without treating them as successful data', async () => {
    const { service, file, configuration } = await setup('tool-error');
    try {
      const { state, result } = await receipt(
        service,
        (
          await submitIdaAnalysis(
            service,
            { file, queries: [{ kind: 'overview' }, { kind: 'bytes', address: '0x0', size: 1 }] },
            configuration,
          )
        ).job_id,
      );
      expect(state.status).toBe('completed');
      expect(result.status).toBe('partial');
      expect(result.queries[0]!.status).toBe('completed');
      expect(result.queries[1]!.status).toBe('failed');
      expect(result.queries[1]!.data).toBeUndefined();
      expect(result.queries[1]!.error?.code).toBe('IDA_TOOL_ERROR');
      expect(JSON.stringify(await raw(service, result))).toContain('cannot read bytes');
    } finally {
      await service.close();
    }
  });
  it('does not promote a failed decompiler to a completed function analysis', async () => {
    const { service, file, configuration } = await setup('decompile-error');
    try {
      const { result } = await receipt(
        service,
        (
          await submitIdaAnalysis(
            service,
            { file, queries: [{ kind: 'function', address: '0x140001000' }] },
            configuration,
          )
        ).job_id,
      );
      expect(result.status).toBe('partial');
      expect(result.queries[0]!.status).toBe('partial');
      expect(result.queries[0]!.data?.pseudocode).toBeUndefined();
      expect(result.queries[0]!.data?.disassembly).toBeTruthy();
      expect(JSON.stringify(await raw(service, result))).toContain('Hex-Rays unavailable');
    } finally {
      await service.close();
    }
  });
  it('rejects a connected database belonging to another input before analysis tools run', async () => {
    const { service, file, configuration } = await setup('wrong-identity');
    try {
      const { state, result } = await receipt(
        service,
        (await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration)).job_id,
      );
      expect(state.status).toBe('failed');
      expect(result.database.identity_verified).toBe(false);
      expect(result.error?.code).toBe('IDA_SOURCE_IDENTITY_MISMATCH');
      expect((await raw(service, result)).some((item) => item.tool === 'server_health')).toBe(false);
    } finally {
      await service.close();
    }
  });
  it('cancels an owned hanging query, saves partial evidence and reaps only its process', async () => {
    const { service, file, configuration } = await setup('hang');
    try {
      const job = await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration);
      let ready = false;
      for (let attempt = 0; attempt < 300; attempt++) {
        try {
          for (const folder of await readdir(path.join(service.store.root, '.ida-work'))) {
            if (
              (await readFile(
                path.join(service.store.root, '.ida-work', folder, 'query-ready'),
                'utf8',
              ).catch(() => null)) === 'ready'
            )
              ready = true;
          }
        } catch {}
        if (ready) break;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      expect(ready).toBe(true);
      await service.jobs.cancel(job.job_id);
      const { state, result } = await receipt(service, job.job_id);
      expect(state.status).toBe('cancelled');
      expect(result.status).toBe('cancelled');
      expect(result.queries[0]?.status).toBe('cancelled');
      expect(result.cleanup.process_closed).toBe(true);
      expect(result.cleanup.idb_closed).toBe(true);
      expect(() => process.kill(result.cleanup.pid!, 0)).toThrow();
      expect(await readFile(file)).toEqual(Buffer.from([0x90, 0xc3]));
    } finally {
      await service.close();
    }
  });
  it('publishes a failed timeout receipt rather than dropping the acquired evidence', async () => {
    const { service, file, configuration } = await setup('hang');
    try {
      const { state, result } = await receipt(
        service,
        (
          await submitIdaAnalysis(
            service,
            { file, queries: [{ kind: 'overview' }], timeout_ms: 300 },
            configuration,
          )
        ).job_id,
      );
      expect(state.status).toBe('failed');
      expect(result.status).toBe('failed');
      expect(result.error?.code).toBe('TIMEOUT');
      expect(result.cleanup.process_closed).toBe(true);
      expect(result.artifacts.length).toBeGreaterThan(0);
    } finally {
      await service.close();
    }
  });
  it('rejects a database whose runtime revision differs from the administrator pin', async () => {
    const { service, file, configuration } = await setup('wrong-provider');
    try {
      const { state, result } = await receipt(
        service,
        (await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration)).job_id,
      );
      expect(state.status).toBe('failed');
      expect(result.error?.code).toBe('IDA_PROVIDER_IDENTITY_MISMATCH');
      expect(result.database.identity_verified).toBe(false);
    } finally {
      await service.close();
    }
  });
  it('reports incomplete native auto-analysis as partial evidence', async () => {
    const { service, file, configuration } = await setup('incomplete');
    try {
      const { result } = await receipt(
        service,
        (await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration)).job_id,
      );
      expect(result.status).toBe('partial');
      expect(result.database.analysis_completed).toBe(false);
      expect(result.limitations.join(' ')).toContain('auto-analysis');
    } finally {
      await service.close();
    }
  });
  it('does not accept a bytes reply missing the requested bytes', async () => {
    const { service, file, configuration } = await setup('invalid-bytes');
    try {
      const { state, result } = await receipt(
        service,
        (
          await submitIdaAnalysis(
            service,
            { file, queries: [{ kind: 'bytes', address: '0x0', size: 1 }] },
            configuration,
          )
        ).job_id,
      );
      expect(state.status).toBe('failed');
      expect(result.queries[0]!.status).toBe('failed');
      expect(result.queries[0]!.data).toBeUndefined();
      expect(result.queries[0]!.error?.code).toBe('IDA_REPLY_INVALID');
    } finally {
      await service.close();
    }
  });
  it('retains exact wire bytes when upstream JSON integers exceed JavaScript precision', async () => {
    const { service, file, configuration } = await setup('wide-number');
    try {
      const { result } = await receipt(
        service,
        (await submitIdaAnalysis(service, { file, queries: [{ kind: 'types' }] }, configuration)).job_id,
      );
      const transcripts = result.artifacts.filter((ref) => ref.media_type === 'application/x-ndjson');
      expect(transcripts).toHaveLength(1);
      const transcript = (await service.store.readArtifact(transcripts[0]!)).toString('utf8');
      expect(transcript).toContain('18446744073709551615');
      expect(result.queries[0]!.data?.items).toEqual([
        { name: 'example_t', size: null, size_precision: 'unsafe_json_integer' },
      ]);
    } finally {
      await service.close();
    }
  });
  it.each(['excessive-listing', 'malformed-cfg'])(
    'rejects invalid bounded analysis shapes: %s',
    async (mode) => {
      const { service, file, configuration } = await setup(mode);
      try {
        const { result } = await receipt(
          service,
          (
            await submitIdaAnalysis(
              service,
              { file, queries: [{ kind: 'function', address: '0x140001000' }] },
              configuration,
            )
          ).job_id,
        );
        expect(result.status).toBe('partial');
        expect(result.queries[0]!.error?.code).toBe('IDA_REPLY_INVALID');
        if (mode === 'malformed-cfg') expect(result.queries[0]!.data?.basic_blocks).toBeUndefined();
        else expect(result.queries[0]!.data?.disassembly).toBeUndefined();
      } finally {
        await service.close();
      }
    },
  );
  it('rejects source changes while preserving the original immutable input evidence', async () => {
    const { service, file, configuration } = await setup('source-change');
    try {
      const { state, result } = await receipt(
        service,
        (await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration)).job_id,
      );
      expect(state.status).toBe('failed');
      expect(result.error?.code).toBe('SOURCE_CHANGED');
      expect(result.validation.source_unchanged).toBe(false);
      expect(await service.store.readArtifact(result.source.artifact)).toEqual(Buffer.from([0x90, 0xc3]));
    } finally {
      await service.close();
    }
  });
  it('does not label bytes returned from another address as the requested address', async () => {
    const { service, file, configuration } = await setup('wrong-address');
    try {
      const { result } = await receipt(
        service,
        (
          await submitIdaAnalysis(
            service,
            { file, queries: [{ kind: 'bytes', address: '0x1000', size: 1 }] },
            configuration,
          )
        ).job_id,
      );
      expect(result.status).toBe('failed');
      expect(result.queries[0]!.error?.code).toBe('IDA_REPLY_INVALID');
      expect(result.queries[0]!.data).toBeUndefined();
    } finally {
      await service.close();
    }
  });
  it('never sends database-close commands to an unverified database owner', async () => {
    const { service, file, configuration } = await setup('unowned-database');
    try {
      const { result } = await receipt(
        service,
        (await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration)).job_id,
      );
      expect(result.status).toBe('failed');
      expect(result.cleanup).toMatchObject({ idb_closed: false, process_closed: true });
      expect((await raw(service, result)).some((item) => item.tool === 'ida_close')).toBe(false);
    } finally {
      await service.close();
    }
  });
  it('retains a terminal cancellation receipt if cancellation arrives during immutable publication', async () => {
    const { service, file, configuration } = await setup();
    const original = service.store.putObject.bind(service.store);
    let enter!: () => void,
      release!: () => void,
      blocked = false;
    const entered = new Promise<void>((resolve) => {
        enter = resolve;
      }),
      gate = new Promise<void>((resolve) => {
        release = resolve;
      });
    service.store.putObject = async (kind: string, objectId: string, value: unknown) => {
      await original(kind, objectId, value);
      if (!blocked && kind === 'runs') {
        blocked = true;
        enter();
        await gate;
      }
    };
    try {
      const job = await submitIdaAnalysis(service, { file, queries: [{ kind: 'overview' }] }, configuration);
      await entered;
      const cancelling = service.jobs.cancel(job.job_id);
      release();
      await cancelling;
      const { state, result } = await receipt(service, job.job_id);
      expect(state.status).toBe('cancelled');
      expect(result.status).toBe('cancelled');
      expect(result.supersedes_result_id).toBeTruthy();
      const previous = (await service.getResult(result.supersedes_result_id!)) as IdaAnalysisResult;
      expect(previous.status).toBe('completed');
    } finally {
      release();
      await service.close();
    }
  });
});
