import {afterEach,describe,expect,it,vi} from 'vitest';
import fsPromises,{mkdtemp,writeFile,readFile,mkdir,link,symlink,realpath,lstat,rm,open,rename,unlink} from 'node:fs/promises';
import {syncBuiltinESMExports} from 'node:module';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {readAcquisitionFile,assertNewAcquisitionOutput,writeAcquisitionJson,writeAcquisitionText} from '../src/native-acquisition-files.js';
const owned:string[]=[];
afterEach(async()=>{for(const directory of owned.splice(0)){const actual=await realpath(directory),temporary=await realpath(tmpdir());if(path.dirname(actual)!==temporary||!path.basename(actual).startsWith('wirefit-acquire-files-')||(await lstat(directory)).isSymbolicLink())throw Error('Unsafe test cleanup');await rm(actual,{recursive:true,force:true});}});
async function fixture(){const dir=await mkdtemp(path.join(tmpdir(),'wirefit-acquire-files-'));owned.push(dir);return dir;}
async function atHandleBoundary(file:string,method:'stat'|'read',action:()=>Promise<void>,run:()=>Promise<unknown>){
 const probe=await open(file,'r'),prototype=Object.getPrototypeOf(probe);await probe.close();
 const original=prototype[method];let triggered=false;
 const spy=vi.spyOn(prototype,method).mockImplementation(async function(this:unknown,...args:unknown[]){
  if(!triggered){triggered=true;await action();}
  return Reflect.apply(original,this,args);
 });
 try{await run();expect(triggered,'The retained FileHandle boundary must actually execute').toBe(true);}finally{spy.mockRestore();}
}
async function atOpenBoundary(file:string,action:()=>Promise<void>,run:()=>Promise<unknown>){
 const original=fsPromises.open;let triggered=false;
 const spy=vi.spyOn(fsPromises,'open').mockImplementation(async(selected,...args)=>{
  if(String(selected)===file&&!triggered){triggered=true;await action();}
  return original(selected,...args);
 });
 syncBuiltinESMExports();
 try{await run();expect(triggered,'The real open boundary must actually execute').toBe(true);}finally{spy.mockRestore();syncBuiltinESMExports();}
}
describe('acquisition file ownership',()=>{
 it('snapshots UTF-8 bytes and size/hash from a retained ordinary file',async()=>{const dir=await fixture(),file=path.join(dir,'input.json');await writeFile(file,'{"内容":"值"}','utf8');const got=await readAcquisitionFile(file,1024,true);expect(got.path).toBe(file);expect(got.bytes.toString('utf8')).toBe('{"内容":"值"}');expect(got.size_bytes).toBe(Buffer.byteLength('{"内容":"值"}','utf8'));expect(got.sha256).toMatch(/^[a-f0-9]{64}$/);});
 it('rejects oversize and multi-link output while permitting fixed read-only inputs',async()=>{const dir=await fixture(),file=path.join(dir,'data');await writeFile(file,'abc','utf8');await expect(readAcquisitionFile(file,2)).rejects.toThrow();await link(file,path.join(dir,'other'));await expect(readAcquisitionFile(file,10,true)).rejects.toThrow();expect((await readAcquisitionFile(file,10,false)).bytes.toString('utf8')).toBe('abc');});
 it('rejects existing output and a junction in the requested parent before creating directories',async()=>{const dir=await fixture(),existing=path.join(dir,'old');await mkdir(existing);await expect(assertNewAcquisitionOutput(existing)).rejects.toThrow();const alias=path.join(dir,'alias');await symlink(existing,alias,process.platform==='win32'?'junction':'dir');await expect(assertNewAcquisitionOutput(path.join(alias,'new'))).rejects.toThrow();await expect(assertNewAcquisitionOutput(path.join(dir,'new'))).resolves.toBeUndefined();});
 it('writes create-new UTF-8 records without replacing older evidence',async()=>{const dir=await fixture(),file=path.join(dir,'receipt.json');await writeAcquisitionJson(file,{text:'测试'});expect(JSON.parse(await readFile(file,'utf8'))).toEqual({text:'测试'});await expect(writeAcquisitionJson(file,{text:'overwritten'})).rejects.toThrow();const log=path.join(dir,'log.txt');await writeAcquisitionText(log,'证据');expect(await readFile(log,'utf8')).toBe('证据');await expect(writeAcquisitionText(log,'lost')).rejects.toThrow();});
 it('classifies a real atomic replacement between entry lstat and HANDLE open as FILE_CHANGED',async()=>{
  const dir=await fixture(),file=path.join(dir,'checkpoint.json'),replacement=path.join(dir,'next.json');
  await writeFile(file,'old checkpoint','utf8');await writeFile(replacement,'new checkpoint','utf8');
  await atOpenBoundary(file,()=>rename(replacement,file),()=>expect(readAcquisitionFile(file,1024,true)).rejects.toMatchObject({code:'ACQUISITION_FILE_CHANGED'}));
  expect(await readFile(file,'utf8')).toBe('new checkpoint');
 });
 it('classifies an in-place ordinary-file mutation during a real HANDLE read as FILE_CHANGED',async()=>{
  const dir=await fixture(),file=path.join(dir,'checkpoint.json');await writeFile(file,'old checkpoint','utf8');
  await atHandleBoundary(file,'read',()=>writeFile(file,'changed checkpoint','utf8'),()=>expect(readAcquisitionFile(file,1024,true)).rejects.toMatchObject({code:'ACQUISITION_FILE_CHANGED'}));
  expect(await readFile(file,'utf8')).toBe('changed checkpoint');
 });
 it('classifies an ordinary path disappearing after HANDLE open as FILE_CHANGED',async()=>{
  const dir=await fixture(),file=path.join(dir,'checkpoint.json');await writeFile(file,'old checkpoint','utf8');
  await atHandleBoundary(file,'read',()=>unlink(file),()=>expect(readAcquisitionFile(file,1024,true)).rejects.toMatchObject({code:'ACQUISITION_FILE_CHANGED'}));
 });
 it('does not classify a new hardlink during HANDLE read as a retryable file change',async()=>{
  const dir=await fixture(),file=path.join(dir,'checkpoint.json');await writeFile(file,'checkpoint','utf8');
  await atHandleBoundary(file,'read',()=>link(file,path.join(dir,'alias.json')),()=>expect(readAcquisitionFile(file,1024,true)).rejects.toMatchObject({code:'ACQUISITION_PATH_INVALID'}));
 });
 it('does not classify a size-bound violation during HANDLE read as a retryable file change',async()=>{
  const dir=await fixture(),file=path.join(dir,'checkpoint.json');await writeFile(file,'old','utf8');
  await atHandleBoundary(file,'read',()=>writeFile(file,'too large','utf8'),()=>expect(readAcquisitionFile(file,4,true)).rejects.toMatchObject({code:'ACQUISITION_PATH_INVALID'}));
 });
 it('does not classify a junction replacement, including a missing child path, as retryable',async()=>{
  const dir=await fixture(),container=path.join(dir,'current'),saved=path.join(dir,'previous'),other=path.join(dir,'other');
  await mkdir(container);await mkdir(other);const file=path.join(container,'checkpoint.json');await writeFile(file,'checkpoint','utf8');
  await atOpenBoundary(file,async()=>{await rename(container,saved);await symlink(other,container,process.platform==='win32'?'junction':'dir');},()=>expect(readAcquisitionFile(file,1024,true)).rejects.toMatchObject({code:'ACQUISITION_PATH_INVALID'}));
 });
});
