import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,writeFile,readFile,mkdir,realpath,rm} from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {prepareAcquisition} from '../src/native-acquisition-prepare.js';
const owned:string[]=[];
afterEach(async()=>{for(const directory of owned.splice(0)){const actual=await realpath(directory),temporary=await realpath(tmpdir());if(path.dirname(actual)!==temporary||!path.basename(actual).startsWith('wirefit-acquire-prepare-'))throw Error('Unsafe cleanup');await rm(actual,{recursive:true,force:true});}});
async function fixture(){
 const dir=await mkdtemp(path.join(tmpdir(),'wirefit-acquire-prepare-'));owned.push(dir);
 const bytes=Buffer.alloc(1024);bytes.write('MZ');bytes.writeUInt32LE(128,60);bytes.write('PE\0\0',128);bytes.writeUInt16LE(0x14c,132);bytes.writeUInt16LE(1,134);bytes.writeUInt16LE(224,148);
 const o=152;bytes.writeUInt16LE(0x10b,o);bytes.writeUInt32LE(4096,o+16);bytes.writeUInt32LE(0x400000,o+28);bytes.writeUInt32LE(4096,o+32);bytes.writeUInt32LE(512,o+36);bytes.writeUInt32LE(8192,o+56);bytes.writeUInt32LE(512,o+60);bytes.writeUInt32LE(16,o+92);
 const s=o+224;bytes.write('.text',s);bytes.writeUInt32LE(512,s+8);bytes.writeUInt32LE(4096,s+12);bytes.writeUInt32LE(512,s+16);bytes.writeUInt32LE(512,s+20);bytes.writeUInt32LE(0x60000020,s+36);bytes[512]=0xc3;
 const options={file:path.join(dir,'fixture.exe'),config:path.join(dir,'config.json'),plan:path.join(dir,'plan.json'),out:path.join(dir,'capture'),python:path.join(dir,'explicit-interpreter'),capture_at_ms:0,callers:['0x1000']};
 await writeFile(options.file,bytes);await writeFile(options.python,'not executed','utf8');await writeFile(options.config,JSON.stringify({command:process.execPath,args:['independent-worker.mjs']}),'utf8');
 const plan={duration_ms:5000,breakpoints_rva:[],ranges:[{rva:'0x1000',size_bytes:1}],api_hooks:[],max_events:16};await writeFile(options.plan,JSON.stringify(plan),'utf8');return {dir,options,plan,bytes};
}
describe('acquisition preflight before child creation',()=>{
 it('binds the actual input bytes and validates the plan without creating output',async()=>{const f=await fixture();const result=await prepareAcquisition(f.options);expect(result.source.bytes).toEqual(f.bytes);expect(result.image_size).toBe(8192);expect(result.plan).toEqual(f.plan);expect(result.tool.command).toBe(process.execPath);await expect(readFile(path.join(f.options.out,'request.json'),'utf8')).rejects.toThrow();});
 it.each([{max_events:1},{breakpoints_rva:['0x1000']},{api_hooks:[{module:'KERNEL32.dll',symbol:'ExitProcess'}]},{duration_ms:0},{ranges:[{rva:'0x2000',size_bytes:1}]}])('rejects unusable or active plan %j',async(change)=>{const f=await fixture();await writeFile(f.options.plan,JSON.stringify({...f.plan,...change}),'utf8');await expect(prepareAcquisition(f.options)).rejects.toThrow();});
 it('rejects an offset after the sampling window and an out-of-image caller',async()=>{const f=await fixture();await expect(prepareAcquisition({...f.options,capture_at_ms:5000})).rejects.toThrow();await expect(prepareAcquisition({...f.options,callers:['0x1fff']})).rejects.toThrow();});
 it('refuses existing evidence and PE32+ before starting any command',async()=>{const f=await fixture();await mkdir(f.options.out);await expect(prepareAcquisition(f.options)).rejects.toThrow();f.bytes.writeUInt16LE(0x8664,132);f.bytes.writeUInt16LE(0x20b,152);await writeFile(f.options.file,f.bytes);await expect(prepareAcquisition({...f.options,out:path.join(f.dir,'fresh')})).rejects.toThrow();});
});
