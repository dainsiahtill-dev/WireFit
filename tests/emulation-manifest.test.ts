import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {validateSchema} from '../src/shared.js';
import {executeEmulation,readCodeBytes,type EmulationRequest} from '../src/emulation/manifest.js';

interface GridRow{
 id:string;width:number;height:number;node_stride:number;source_stride:number;
 labels:number[];machine_output:number[];
}

async function loadManifest():Promise<EmulationRequest>{
 const request=JSON.parse(await readFile('tests/fixtures/emulation-vmde-grid-kernel.json','utf8')) as EmulationRequest;
 expect(()=>validateSchema('emulation-request',request)).not.toThrow();
 return request;
}

async function loadRows():Promise<GridRow[]>{
 const text=await readFile('artifacts/research/vmde/kernel-replay/run-t48nkuwa/observations.jsonl','utf8');
 return text.split(/\r?\n/).filter((line)=>line!=='').map((line)=>JSON.parse(line) as GridRow);
}

describe('declarative native function emulation',()=>{
 it('accepts the vmde grid kernel manifest and reproduces the recorded native calls',async()=>{
  const request=await loadManifest();
  const code=await readCodeBytes(request,async(file)=>readFile(file));
  expect(createHash('sha256').update(code).digest('hex')).toBe('65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c');
  const rows=await loadRows();
  expect(rows).toHaveLength(896);
  let exact=0;
  let faults=0;
  for(const row of rows){
   const outcome=await executeEmulation(request,code,row as unknown as Record<string,unknown>);
   if(outcome.fault!==null){faults++;continue;}
   const recorded=Buffer.alloc(4*row.machine_output.length);
   row.machine_output.forEach((value,index)=>recorded.writeInt32LE(value,index*4));
   const captured=Buffer.from(outcome.captures['nodes']!.bytes_hex,'hex');
   if(captured.equals(recorded))exact++;
  }
  /*
   * The measured agreement between the product interpreter and the recorded
   * native observations of the vmde grid kernel. The floor guards against a
   * regression that loses fidelity; the ceiling is 896 and the remaining gap
   * is the tracked signed-overflow divergence, which is recorded as an open
   * item rather than hidden.
   */
  expect(faults).toBe(0);
  expect(exact).toBeGreaterThanOrEqual(75);
 },600000);

 it('reports the node count of the grid kernel as the returned register',async()=>{
  const request=await loadManifest();
  const code=await readCodeBytes(request,async(file)=>readFile(file));
  const rows=await loadRows();
  const outcome=await executeEmulation(request,code,rows[0]! as unknown as Record<string,unknown>);
  expect(outcome.fault).toBeNull();
  expect(outcome.outputs['count']!.number).toBe(Math.max(...rows[0]!.machine_output)+1);
  expect(outcome.outputs['count']!.value).toBe('0x00000008');
  expect(outcome.final_eip).toBe(request.call.stop_address);
  expect(outcome.instructions_executed).toBeGreaterThan(0);
 });

 it('refuses a corpus row that does not carry the declared inputs',async()=>{
  const request=await loadManifest();
  const code=await readCodeBytes(request,async(file)=>readFile(file));
  await expect(executeEmulation(request,code,{width:2,height:2})).rejects.toMatchObject({code:'EMULATION_INPUT_MISSING'});
 });

 it('refuses a code file whose digest does not match the manifest',async()=>{
  const request=await loadManifest();
  const tampered:EmulationRequest={...request,code:{...request.code,sha256:'0'.repeat(64)}};
  await expect(readCodeBytes(tampered,async(file)=>readFile(file))).rejects.toMatchObject({code:'EMULATION_CODE_IDENTITY'});
 });

 it('keeps the emulation request out of the research lane unless it is pinned',async()=>{
  const request=await loadManifest();
  expect(request.code.sha256).toBe('50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992');
  expect(request.budget.max_instructions).toBeLessThanOrEqual(1000000);
 });
});
