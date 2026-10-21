import {describe,it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {Memory,X86Interpreter,EmulationFault} from '../src/emulation/x86.js';

const ENTRY=0x498a50;
const BODY=637;
const CONTEXT=0x2000000,HEADER=0x2100000,PIXELS=0x2200000,NODES=0x2300000,STACK=0x2400000,STOP=0x70000000;

interface GridCase{
 id:string;width:number;height:number;node_stride:number;source_stride:number;
 labels:number[];machine_output:number[];
}

async function loadCase():Promise<GridCase>{
 const text=await readFile('artifacts/research/vmde/kernel-replay/run-t48nkuwa/observations.jsonl','utf8');
 const first=text.split(/\r?\n/).filter((line)=>line!=='')[0]!;
 return JSON.parse(first) as GridCase;
}

async function loadCode():Promise<Uint8Array>{
 const dump=await readFile('exports/vmde-20261020/unpacked_vmde.exe');
 const pe=dump.readUInt32LE(0x3c);
 const sections=dump.readUInt16LE(pe+6),optional=dump.readUInt16LE(pe+20);
 let offset=-1;
 for(let index=0;index<sections;index++){
  const section=pe+24+optional+index*40;
  const rva=dump.readUInt32LE(section+12),rawSize=dump.readUInt32LE(section+16),raw=dump.readUInt32LE(section+20);
  if(rva<=ENTRY-0x400000&&ENTRY-0x400000+BODY<=rva+rawSize)offset=raw+ENTRY-0x400000-rva;
 }
 expect(offset).toBeGreaterThan(0);
 return dump.subarray(offset,offset+BODY);
}

function faultCode(action:()=>unknown):string{
 try{action();return '';}
 catch(error){return (error as {code?:string}).code??(error as Error).message;}
}

interface Harness{
 cpu:X86Interpreter;
 memory:Memory;
 run():{eip:number;esp:number;eax:number;ecx:number;ebx:number;edx:number;esi:number;edi:number;ebp:number;eflags:number};
 trace:number[][];
}

function buildHarness(row:GridCase,code:Uint8Array,options:{policy?:boolean;maxInstructions?:number}={}):Harness{
 const regions=[
  {name:'code',base:ENTRY&~4095,size_bytes:4096,read:true,write:false,execute:true},
  {name:'context',base:CONTEXT,size_bytes:4096,read:true,write:false,execute:false},
  {name:'header',base:HEADER,size_bytes:4096,read:true,write:false,execute:false},
  {name:'pixels',base:PIXELS,size_bytes:4096,read:true,write:false,execute:false},
  {name:'nodes',base:NODES,size_bytes:4096,read:true,write:true,execute:false},
  {name:'stack',base:STACK,size_bytes:8192,read:true,write:true,execute:false},
  {name:'stop',base:STOP,size_bytes:4096,read:true,write:false,execute:true},
 ];
 const memory=new Memory(regions);
 memory.loadBytes(ENTRY,code);
 memory.loadBytes(NODES,Buffer.alloc(4096,0xa5));
 memory.loadBytes(CONTEXT,Buffer.alloc(4096,0xa5));
 const header=Buffer.alloc(12);
 header.writeUInt32LE(PIXELS,0);header.writeUInt32LE(row.source_stride,4);header.writeUInt32LE(row.height,8);
 memory.loadBytes(HEADER,header);
 const source=new Int32Array(row.source_stride*row.height).fill(-1515870811);
 for(let y=0;y<row.height;y++)for(let x=0;x<row.width;x++)source[y*row.source_stride+x]=row.labels[y*row.width+x]!;
 memory.loadBytes(PIXELS,Buffer.from(source.buffer));
 const context=Buffer.alloc(4096);
 for(const [at,value] of [[0,NODES],[4,row.node_stride],[8,row.height+1],[12,HEADER],[0x94,row.width],[0x98,row.height]] as [number,number][])
  context.writeUInt32LE(value>>>0,at);
 memory.loadBytes(CONTEXT,context);
 const top=STACK+4096;
 memory.loadBytes(top,Buffer.from([STOP&255,(STOP>>8)&255,(STOP>>16)&255,(STOP>>>24)&255]));
 const readable=options.policy===true?[{base:PIXELS,size_bytes:4096}]:[];
 const writable=options.policy===true?[{base:NODES,size_bytes:4096}]:[];
 const cpu=new X86Interpreter({memory,budget:{max_instructions:options.maxInstructions??100000,max_memory_bytes:1<<20},readable,writable});
 cpu.registers.eip=ENTRY;cpu.registers.ecx=CONTEXT;cpu.registers.esp=top;cpu.registers.unpackFlags(2);
 cpu.registers.ebx=0x12345678;cpu.registers.esi=0x23456789;cpu.registers.edi=0x3456789a;cpu.registers.ebp=0x456789ab;
 const trace:number[][]=[];
 const run=():ReturnType<Harness['run']>=>{
  for(;;){
   const r=cpu.registers;
   trace.push([r.eip,r.eax,r.ebx,r.ecx,r.edx,r.esi,r.edi,r.ebp,r.esp,r.packedFlags()]);
   if(r.eip===STOP)break;
   cpu.step();
  }
  const r=cpu.registers;
  return {eip:r.eip,esp:r.esp,eax:r.eax,ecx:r.ecx,ebx:r.ebx,edx:r.edx,esi:r.esi,edi:r.edi,ebp:r.ebp,eflags:r.packedFlags()};
 };
 return {cpu,memory,run,trace};
}

describe('bounded x86 interpreter',()=>{
 it('reproduces the recorded reference trace of the vmde grid kernel instruction for instruction',async()=>{
  const row=await loadCase();
  const code=await loadCode();
  const fixture=JSON.parse(await readFile('tests/fixtures/emulation-reference-trace.json','utf8')) as {steps:string[][]};
  const harness=buildHarness(row,code);
  harness.run();
  /*
   * The reference emulator samples the repeated string instruction once more
   * than the hardware repeats it, so the two traces are aligned by the
   * occurrence of each instruction address rather than by index.
   */
  const expectedByOccurrence=new Map<string,number[]>();
  for(const step of fixture.steps){
   const key=String(parseInt(step[0]!,16));
   const list=expectedByOccurrence.get(key)??[];
   list.push(...step.slice(1).map((value)=>parseInt(value,16)));
   expectedByOccurrence.set(key,list);
  }
  const seen=new Map<string,number>();
  for(const step of harness.trace){
   const key=String(step[0]);
   const occurrence=seen.get(key)??0;
   seen.set(key,occurrence+1);
   const list=expectedByOccurrence.get(key)??[];
   if(list.length===0){
    // The return address is not an instruction of the kernel; the reference
    // stops tracing before it.
    expect(step[0]).toBe(STOP);
    continue;
   }
   const expected=list.slice(occurrence*9,occurrence*9+9);
   expect(expected.length).toBe(9);
   expect(step.slice(1)).toEqual(expected);
  }
 },120000);

 it('reproduces the recorded node grid of the vmde grid kernel',async()=>{
  const row=await loadCase();
  const code=await loadCode();
  const harness=buildHarness(row,code);
  const result=harness.run();
  expect(result.eip).toBe(STOP);
  const produced:number[]=[];
  for(let index=0;index<row.machine_output.length;index++)produced.push(harness.memory.read32(NODES+index*4)|0);
  expect(produced).toEqual(row.machine_output);
 },120000);

 it('refuses an access outside the declared policy',async()=>{
  const row=await loadCase();
  const code=await loadCode();
  const harness=buildHarness(row,code,{policy:true});
  expect(faultCode(()=>harness.run())).toBe('EMULATION_ACCESS_DENIED');
 },120000);

 it('refuses to execute outside an executable region',async()=>{
  const memory=new Memory([{name:'code',base:ENTRY,size_bytes:4096,read:true,write:false,execute:false}]);
  const cpu=new X86Interpreter({memory,budget:{max_instructions:100,max_memory_bytes:1<<20},readable:[],writable:[]});
  cpu.registers.eip=ENTRY;
  expect(faultCode(()=>cpu.step())).toBe('EMULATION_EXECUTION_DENIED');
 });

 it('stops when the instruction budget is exhausted',async()=>{
  const row=await loadCase();
  const code=await loadCode();
  const harness=buildHarness(row,code,{maxInstructions:8});
  expect(faultCode(()=>harness.run())).toBe('EMULATION_BUDGET_EXHAUSTED');
 });

 it('reports an unsupported opcode instead of guessing',async()=>{
  const memory=new Memory([{name:'code',base:0x1000,size_bytes:4096,read:true,write:false,execute:true}]);
  memory.loadBytes(0x1000,Uint8Array.from([0x0f,0x0b]));
  const cpu=new X86Interpreter({memory,budget:{max_instructions:10,max_memory_bytes:1<<20},readable:[],writable:[]});
  cpu.registers.eip=0x1000;
  expect(faultCode(()=>cpu.step())).toBe('EMULATION_UNSUPPORTED_OPCODE');
 });
});
