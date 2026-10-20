import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,mkdir,readFile,realpath,rm,writeFile,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {runProcess} from '../src/process.js';

const worker=fileURLToPath(new URL('../tools/native-trace/memory-image.py',import.meta.url));
const owned:string[]=[];
afterEach(async()=>{for(const directory of owned.splice(0)){
 const resolved=await realpath(directory),temporaryRoot=await realpath(tmpdir());
 if(path.dirname(resolved)!==temporaryRoot||!path.basename(resolved).startsWith('wirefit-memory-image-'))throw new Error('Refusing cleanup outside owned temporary directory');
 await rm(resolved,{recursive:true,force:true});
}});
async function fixture(){const directory=await mkdtemp(path.join(tmpdir(),'wirefit-memory-image-'));owned.push(directory);return directory;}
async function python(code:string,directory:string,args:string[]=[]){
 return runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker,...args],{cwd:directory,timeout_ms:15000});
}
const load="import json,sys;from pathlib import Path;ns={'__name__':'memory_image_test','__file__':sys.argv[1]};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns)";

describe('external memory-image boundaries without target execution',()=>{
 it.each([['--pid','0'],['--pid','-1'],['--size','67108865'],['--size','0'],['--base','0x10000000000000000'],['--expected-start-filetime','-1'],['--expected-exe','relative.exe'],['--out','relative-prefix']])('rejects invalid %s %s before opening a process',async(option,value)=>{
  const directory=await fixture();const source=path.join(directory,'source.exe');await writeFile(source,'not executed','utf8');
  const args=['--pid','1234','--expected-exe',source,'--expected-start-filetime','1234','--base','0x400000','--size','4096','--out',path.join(directory,'capture')];
  args[args.indexOf(option)+1]=value;
  const result=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S',worker,...args],{cwd:directory,timeout_ms:10000});
  expect(result.stdout.trim(),'invalid input must produce structured failure').not.toBe('');
  expect(result.code).toBe(1);expect(JSON.parse(result.stdout).error.code).toBe('INVALID_ARGUMENTS');
  expect(await readdir(directory)).toEqual(['source.exe']);
 });
 it('preserves initial partial bytes when page retry fails and marks only unseen bytes as zero gaps',async()=>{
  const directory=await fixture();
  const code=load+"\nimport hashlib\nclass Reader:\n def read(self,address,length):\n  if length==12288:return {'data':b'A'*4096,'transferred_bytes':4096,'success':False,'winerror':299}\n  if address==0x402000:return {'data':b'C'*4096,'transferred_bytes':4096,'success':True,'winerror':0}\n  return {'data':b'','transferred_bytes':0,'success':False,'winerror':299}\nimage=bytearray(12288)\ndef write_at(offset,data):image[offset:offset+len(data)]=data\nresult=ns['read_segments'](Reader(),0x400000,len(image),write_at);print(json.dumps({'coverage':result,'first':image[:1].hex(),'hole':image[4096:8192].hex(),'last':image[8192:8193].hex()}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.coverage.observed_bytes).toBe(8192);expect(result.coverage.unobserved_bytes).toBe(4096);
  expect(result.first).toBe('41');expect(result.hole).toBe('00'.repeat(4096));expect(result.last).toBe('43');
  expect(result.coverage.pages[1]).toMatchObject({rva:'0x1000',observed_bytes:0,coverage_complete:false,observed_sha256:null});
  expect(result.coverage.pages[1].attempts.at(-1)).toMatchObject({success:false,winerror:299,transferred_bytes:0});
 });
 it('bounds zero-byte successful reads and rejects impossible transfer counts',async()=>{
  const directory=await fixture();
  const code=load+"\nclass Reader:\n calls=0\n def read(self,address,length):\n  self.calls+=1;return {'data':b'','transferred_bytes':0,'success':True,'winerror':0}\nr=Reader();zero=ns['read_segments'](r,0x400000,4096,lambda offset,data:None)\nclass Bad:\n def read(self,address,length):return {'data':b'x','transferred_bytes':10,'success':False,'winerror':299}\ntry:ns['read_segments'](Bad(),0x400000,4096,lambda offset,data:None)\nexcept Exception as e:failure=e.code\nprint(json.dumps({'calls':r.calls,'zero':zero,'failure':failure}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.calls).toBe(2);expect(result.zero.observed_bytes).toBe(0);expect(result.zero.unobserved_bytes).toBe(4096);expect(result.failure).toBe('INVALID_READ_RESULT');
 });
 it('retains all initial chunk evidence when a retry raises and counts shorter retries only once',async()=>{
  const directory=await fixture();
  const code=load+"\nclass Reader:\n def read(self,address,length):\n  if length==12288:return {'data':b'A'*8192,'transferred_bytes':8192,'success':False,'winerror':299}\n  raise RuntimeError('synthetic retry failure')\nimage=bytearray(12288)\ndef write_at(offset,data):image[offset:offset+len(data)]=data\ntry:ns['read_segments'](Reader(),0x400000,len(image),write_at)\nexcept Exception as e:coverage=e.coverage\nclass Short:\n def read(self,address,length):\n  if length==8192:return {'data':b'A'*3000,'transferred_bytes':3000,'success':False,'winerror':299}\n  if address==0x400000:return {'data':b'B'*1000,'transferred_bytes':1000,'success':False,'winerror':299}\n  return {'data':b'','transferred_bytes':0,'success':False,'winerror':5}\nshort=ns['read_segments'](Short(),0x400000,8192,lambda offset,data:None)\nprint(json.dumps({'coverage':coverage,'prefix':image[:8192].hex(),'short':short}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.prefix).toBe('41'.repeat(8192));expect(result.coverage.observed_bytes).toBe(8192);expect(result.coverage.unobserved_bytes).toBe(4096);
  expect(result.short.observed_bytes).toBe(3000);expect(result.short.pages[0].observed_sha256).toBe(createHash('sha256').update('B'.repeat(1000)+'A'.repeat(2000)).digest('hex'));
 });
 it('invalidates uncertain output after a retry write error and binds a known short-write prefix accurately',async()=>{
  const directory=await fixture();
  const code=load+"\nclass Reader:\n def read(self,address,length):\n  if length==8192:return {'data':b'A'*3000,'transferred_bytes':3000,'success':False,'winerror':299}\n  return {'data':b'B'*1000,'transferred_bytes':1000,'success':False,'winerror':299}\ndef run(known):\n image=bytearray(8192)\n def write_at(offset,data):\n  if data[:1]==b'B':\n   image[offset:offset+100]=data[:100];error=ns['MemoryImageError']('OUTPUT_WRITE_FAILED','synthetic short write')\n   if known:error.written_prefix_bytes=100\n   raise error\n  image[offset:offset+len(data)]=data\n try:ns['read_segments'](Reader(),0x400000,8192,write_at)\n except Exception as error:return {'coverage':error.coverage,'actual_sha256':__import__('hashlib').sha256(image[:3000]).hexdigest()}\nprint(json.dumps({'unknown':run(False),'known':run(True)}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.unknown.coverage.pages[0]).toMatchObject({observed_bytes:0,observed_sha256:null,output_bytes_unverified:true});expect(result.unknown.coverage.pages[0].attempts).toHaveLength(2);expect(result.unknown.coverage.unverified_output_bytes).toBe(4096);
  expect(result.known.coverage.pages[0].observed_bytes).toBe(3000);expect(result.known.coverage.pages[0].observed_sha256).toBe(result.known.actual_sha256);expect(result.known.coverage.pages[0].attempts.at(-1).output_write).toMatchObject({success:false,written_prefix_bytes:100});
 });
 it('stops without target reads and records a disjoint unobserved tail',async()=>{
  const directory=await fixture();const code=load+"\nclass Never:\n def read(self,address,length):raise RuntimeError('unexpected read')\ncoverage=ns['read_segments'](Never(),0x400000,100000,lambda offset,data:None,lambda:'process_exited');print(json.dumps(coverage))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.observed_bytes).toBe(0);expect(result.unobserved_bytes).toBe(100000);expect(result.stopped_reason).toBe('process_exited');
  expect(result.pages.map((page:{rva:string,requested_bytes:number})=>[page.rva,page.requested_bytes])).toEqual([['0x0',65536],['0x10000',34464]]);
 });
 it('keeps image bytes and a failed receipt after a later read error and closes its retained identities',async()=>{
  const directory=await fixture();await writeFile(path.join(directory,'source.exe'),'never executed','utf8');
  const code=load+"\nheader={'machine':332,'size_of_image':100000,'preferred_image_base':4194304}\nclass Source:\n def __init__(self,path):self.header=header\n def __enter__(self):return self\n def verify(self):pass\n def close(self):pass\n def receipt(self):return {'sha256':'0'*64,'verified_stable':True}\nclass Reader:\n def __init__(self,pid):self.pid=pid\n def identity(self):return {'pid':self.pid,'executable':str(Path('source.exe').resolve()),'creation_filetime':'1234','alive':True}\n def close(self):pass\n def read(self,address,length):\n  if address==0x400000:return {'data':b'A'*length,'transferred_bytes':length,'success':True,'winerror':0}\n  raise RuntimeError('synthetic second chunk failure')\nns['SourceSnapshot']=Source;ns['WindowsMemoryReader']=Reader;ns['live_pe_header']=lambda reader,base:header\nconfig=ns['parse_arguments'](['--pid','1234','--expected-exe',str(Path('source.exe').resolve()),'--expected-start-filetime','1234','--base','0x400000','--size','100000','--out',str(Path('capture').resolve())]);result=ns['capture_memory_image'](config);print(json.dumps(result))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('failed');expect(result.error.code).toBe('MEMORY_READ_FAILED');expect(result.cleanup).toEqual({process_handle_closed:true,source_handle_closed:true});
  expect(result.coverage.observed_bytes).toBe(65536);expect(result.coverage.unobserved_bytes).toBe(34464);
  const bytes=await readFile(path.join(directory,'capture.bin'));expect(bytes.subarray(0,65536)).toEqual(Buffer.alloc(65536,65));expect(bytes.subarray(65536)).toEqual(Buffer.alloc(34464));
  expect(JSON.parse(await readFile(path.join(directory,'capture.json'),'utf8'))).toEqual(result);
 });
 it('refuses either existing output without modifying evidence',async()=>{
  const directory=await fixture(),source=path.join(directory,'source.exe'),prefix=path.join(directory,'capture');await writeFile(source,'never executed','utf8');await writeFile(prefix+'.bin','existing evidence','utf8');
  const execution=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S',worker,'--pid','1234','--expected-exe',source,'--expected-start-filetime','1234','--base','0x400000','--size','4096','--out',prefix],{cwd:directory,timeout_ms:10000});
  expect(execution.code).toBe(1);expect(JSON.parse(execution.stdout).error.code).toBe('OUTPUT_EXISTS');expect(await readFile(prefix+'.bin','utf8')).toBe('existing evidence');expect((await readdir(directory)).sort()).toEqual(['capture.bin','source.exe']);
 });
 it('keeps maximum-range page retry metadata below the bounded receipt envelope',async()=>{
  const directory=await fixture();
  const code=load+"\nclass Reader:\n def read(self,address,length):\n  data=b'A'*(length-1);return {'data':data,'transferred_bytes':len(data),'success':False,'winerror':4294967295}\ncoverage=ns['read_segments'](Reader(),0x400000,67108864,lambda offset,data:None);size=len(json.dumps(coverage,separators=(',',':')).encode('utf-8'));print(json.dumps({'bytes':size,'pages':len(coverage['pages'])}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.pages).toBe(16384);expect(result.bytes).toBeLessThan(15*1024*1024);
 });
 it('accepts an actual ASLR base distinct from the preferred image base',async()=>{
  const directory=await fixture();const code=load+";source={'machine':332,'size_of_image':8192,'preferred_image_base':4194304};live={**source,'preferred_image_base':5242880};ns['validate_image_headers'](source,live,0x500000,8192);print(json.dumps({'accepted':True}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);expect(JSON.parse(execution.stdout)).toEqual({accepted:true});
 });
 it('records legal runtime entry-point and ImageBase changes without rejecting the bound image',async()=>{
  const directory=await fixture();const code=load+";source={'machine':332,'size_of_image':8192,'entry_point_rva':4096,'preferred_image_base':4194304};live={**source,'entry_point_rva':8191,'preferred_image_base':5242880};differences=ns['validate_image_headers'](source,live,0x500000,8192);print(json.dumps(differences))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);expect(JSON.parse(execution.stdout)).toEqual([{field:'entry_point_rva',source_value:4096,live_value:8191},{field:'preferred_image_base',source_value:4194304,live_value:5242880}]);
 });
 it.each(['machine','size_of_image','optional_magic','number_of_sections','time_date_stamp','pe_offset','size_of_headers'])('still rejects immutable %s mismatch when entry-point fields also changed',async(field)=>{
  const directory=await fixture();const code=load+";source={'machine':332,'size_of_image':8192,'entry_point_rva':4096,'preferred_image_base':4194304,'optional_magic':267,'number_of_sections':1,'time_date_stamp':10,'pe_offset':128,'size_of_headers':512};live={**source,'entry_point_rva':8191};live[sys.argv[2]]+=1\ntry:ns['validate_image_headers'](source,live,0x500000,8192)\nexcept Exception as error:print(json.dumps({'code':error.code}))";
  const execution=await python(code,directory,[field]);expect(execution.code,execution.stderr).toBe(0);expect(JSON.parse(execution.stdout)).toEqual({code:'IMAGE_MISMATCH'});
 });
 it('rejects an out-of-image runtime entry point instead of treating it as an allowed header mutation',async()=>{
  const directory=await fixture();const code=load+";source={'machine':332,'size_of_image':8192,'entry_point_rva':4096};live={**source,'entry_point_rva':8192}\ntry:ns['validate_image_headers'](source,live,0x500000,8192)\nexcept Exception as error:print(json.dumps({'code':error.code}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);expect(JSON.parse(execution.stdout)).toEqual({code:'INVALID_PE_HEADER'});
 });
 it.each([false,true])('preserves observed headers for mutable entry-point capture or immutable rejection (%s)',async(immutableMismatch)=>{
  const directory=await fixture();await writeFile(path.join(directory,'source.exe'),'never executed','utf8');
  const code=load+"\nheader={'machine':332,'size_of_image':100000,'preferred_image_base':4194304,'entry_point_rva':4096,'time_date_stamp':10};live={**header,'entry_point_rva':8192}\nif sys.argv[2]=='true':live['time_date_stamp']=11\nclass Source:\n def __init__(self,path):self.header=header\n def __enter__(self):return self\n def verify(self):pass\n def close(self):pass\n def receipt(self):return {'sha256':'0'*64,'header':header,'verified_stable':True}\nclass Reader:\n def __init__(self,pid):self.pid=pid\n def identity(self):return {'pid':self.pid,'executable':str(Path('source.exe').resolve()),'creation_filetime':'1234','alive':True}\n def close(self):pass\n def read(self,address,length):return {'data':b'A'*length,'transferred_bytes':length,'success':True,'winerror':0}\nns['SourceSnapshot']=Source;ns['WindowsMemoryReader']=Reader;ns['live_pe_header']=lambda reader,base:live\nconfig=ns['parse_arguments'](['--pid','1234','--expected-exe',str(Path('source.exe').resolve()),'--expected-start-filetime','1234','--base','0x400000','--size','100000','--out',str(Path('capture').resolve())]);print(json.dumps(ns['capture_memory_image'](config)))";
  const execution=await python(code,directory,[String(immutableMismatch)]);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.live_header).toMatchObject({entry_point_rva:8192,time_date_stamp:immutableMismatch?11:10});expect(result.source.header.entry_point_rva).toBe(4096);expect(result.cleanup).toEqual({process_handle_closed:true,source_handle_closed:true});
  if(immutableMismatch){expect(result).toMatchObject({status:'failed',error:{code:'IMAGE_MISMATCH'}});expect(await readdir(directory)).toEqual(['source.exe']);}
  else{expect(result.status).toBe('completed');expect(result.mutable_header_differences).toEqual([{field:'entry_point_rva',source_value:4096,live_value:8192}]);expect((await readFile(path.join(directory,'capture.bin'))).length).toBe(100000);expect(JSON.parse(await readFile(path.join(directory,'capture.json'),'utf8')).mutable_header_differences).toEqual(result.mutable_header_differences);}
 });
 it.skipIf(process.platform!=='win32')('binds and captures only its own current Python image with explicit coverage and source identity',async()=>{
  const directory=await fixture();await mkdir(path.join(directory,'output'));
  const code=load+"\nimport os,ctypes\nkernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.GetModuleHandleW.argtypes=[ctypes.c_wchar_p];kernel.GetModuleHandleW.restype=ctypes.c_void_p\nwith ns['WindowsMemoryReader'](os.getpid()) as reader:\n identity=reader.identity();base=kernel.GetModuleHandleW(None);header=ns['live_pe_header'](reader,base)\nargs=['--pid',str(os.getpid()),'--expected-exe',sys.executable,'--expected-start-filetime',str(identity['creation_filetime']),'--base',hex(base),'--size',str(header['size_of_image']),'--out',str(Path('output/self').resolve())];result=ns['capture_memory_image'](ns['parse_arguments'](args));args[5]=str(int(identity['creation_filetime'])+1);args[-1]=str(Path('output/mismatch').resolve());mismatch=ns['capture_memory_image'](ns['parse_arguments'](args));print(json.dumps({'capture':result,'mismatch':mismatch}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const wrapper=JSON.parse(execution.stdout),result=wrapper.capture;
  expect(wrapper.mismatch).toMatchObject({status:'failed',error:{code:'PROCESS_IDENTITY_MISMATCH'},cleanup:{process_handle_closed:true,source_handle_closed:true}});
  expect(['completed','partial']).toContain(result.status);expect(result.identity.start.creation_filetime).toBe(result.identity.end.creation_filetime);
  expect(result.coverage.observed_bytes).toBeGreaterThan(64);expect(result.coverage.observed_bytes+result.coverage.unobserved_bytes).toBe(result.size_bytes);
  expect(result.atomic).toBe(false);expect(result.runnable_pe).toBe(false);expect(result.unobserved_fill).toBe('zero');
  expect(result.tool.sha256).toBe(createHash('sha256').update(await readFile(worker)).digest('hex'));expect(result.tool.size_bytes).toBe((await readFile(worker)).length);expect(typeof result.identity.start.creation_filetime).toBe('string');
  const bytes=await readFile(path.join(directory,'output/self.bin'));expect(bytes.length).toBe(result.size_bytes);expect(createHash('sha256').update(bytes).digest('hex')).toBe(result.image.sha256);
  expect(JSON.parse(await readFile(path.join(directory,'output/self.json'),'utf8')).image.sha256).toBe(result.image.sha256);
  expect((await readdir(path.join(directory,'output'))).sort()).toEqual(['self.bin','self.json']);
 });
});
