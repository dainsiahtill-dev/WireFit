import {afterEach,describe,expect,it} from 'vitest';
import {mkdtemp,readdir,readFile,realpath,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {runProcess} from '../src/process.js';

const worker=fileURLToPath(new URL('../tools/native-trace/private-regions.py',import.meta.url));
const owned:string[]=[];
afterEach(async()=>{for(const directory of owned.splice(0)){
 const resolved=await realpath(directory),temporaryRoot=await realpath(tmpdir());
 if(path.dirname(resolved)!==temporaryRoot||!path.basename(resolved).startsWith('wirefit-private-regions-'))throw new Error('Refusing cleanup outside owned temporary directory');
 await rm(resolved,{recursive:true,force:true});
}});
async function fixture(){const directory=await mkdtemp(path.join(tmpdir(),'wirefit-private-regions-'));owned.push(directory);return directory;}
async function python(code:string,directory:string,args:string[]=[]){
 return runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S','-c',code,worker,...args],{cwd:directory,timeout_ms:15000,max_stdout_bytes:2*1024*1024});
}
const load="import json,sys;from pathlib import Path;ns={'__name__':'private_regions_test','__file__':sys.argv[1]};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns)";
// These are data-only PE headers, never launched or loaded as a PE.
const sourceFixture=`
import hashlib,struct
source=bytearray(1024);source[:2]=b'MZ';struct.pack_into('<I',source,60,128);source[128:132]=b'PE\\0\\0'
struct.pack_into('<HHI',source,132,332,1,10);struct.pack_into('<H',source,148,224)
struct.pack_into('<H',source,152,267);struct.pack_into('<I',source,168,4096);struct.pack_into('<I',source,180,4194304)
struct.pack_into('<II',source,208,8192,512);struct.pack_into('<IIII',source,384,4096,4096,512,512)
source_path=Path('source.exe').resolve();source_path.write_bytes(source)
image=bytearray(8192);image[:512]=source[:512]
for rva,target in [(4096,0x100000),(4112,0x100010)]:image[rva:rva+6]=b'\\xe8'+struct.pack('<i',target-(0x400000+rva+5))+b'\\x90'
image_path=Path('main.bin').resolve();image_path.write_bytes(image)
endpoint={'pid':1234,'executable':str(source_path),'creation_filetime':'1234','alive':True}
receipt={'schema_version':1,'status':'completed','layout':'flat_rva_memory','atomic':False,'runnable_pe':False,'pid':1234,'base':'0x400000','size_bytes':8192,
 'identity':{'expected_executable':str(source_path),'expected_creation_filetime':'1234','start':endpoint,'end':dict(endpoint)},
 'source':{'path':str(source_path),'size_bytes':len(source),'sha256':hashlib.sha256(source).hexdigest(),'verified_stable':True},
 'image':{'file':'main.bin','size_bytes':len(image),'sha256':hashlib.sha256(image).hexdigest()},
 'coverage':{'observed_bytes':8192,'unobserved_bytes':0,'unverified_output_bytes':0,'pages':[{'rva':'0x0','requested_bytes':8192,'observed_bytes':8192,'observed_prefix_bytes':8192,'coverage_complete':True,'observed_sha256':hashlib.sha256(image).hexdigest()}]}}
receipt_path=Path('main.json').resolve()
def save_receipt():receipt_path.write_text(json.dumps(receipt),encoding='utf-8')
save_receipt()
args=['--receipt',str(receipt_path),'--image',str(image_path),'--caller-rva','0x1000','--out',str(Path('capture').resolve())]
def region(base,size=4096,protect=0x20,state=0x1000,allocation=0x100000,kind=0x20000):
 return {'base_address':base,'allocation_base':allocation,'allocation_protect':0x40,'region_size':size,'state':state,'protect':protect,'type':kind,'returned_size':48}
class Reader:
 opened=0;private_reads=0;query_addresses=[];mode='normal'
 def __init__(self,pid,**kwargs):self.pid=pid;Reader.opened+=1
 def identity(self):return dict(endpoint)
 def close(self):pass
 def query(self,address):
  Reader.query_addresses.append(address)
  if 0x400000<=address<0x402000:return region(0x400000,size=8192,allocation=0x400000,kind=0x1000000)
  if address<0x101000:return region(0x100000,protect=0x120 if Reader.mode=='guard' else 0x20)
  if address<0x102000:return region(0x101000,protect=0x04)
  if address<0x103000:return region(0x102000)
  return region(0x103000,state=0x10000,allocation=0,kind=0,protect=0)
 def read(self,address,length):
  if 0x400000<=address<0x402000:
   data=bytes(image[address-0x400000:address-0x400000+length])
   if Reader.mode=='changed':data=b'\\x90'*length
  else:
   Reader.private_reads+=1
   if Reader.mode=='partial' and address==0x100000:data=b'A'*100
   elif Reader.mode=='partial':data=b''
   else:data=b'A'*length
  return {'data':data,'transferred_bytes':len(data),'success':len(data)==length,'winerror':0 if len(data)==length else 299}
ns['WindowsRegionReader']=Reader
`;

describe('bounded private-region capture without target execution',()=>{
 it.each([['--receipt','relative.json'],['--image','relative.bin'],['--caller-rva','-1'],['--caller-rva','0x100000000'],['--out','relative'],['--timeout-ms','0']])('rejects invalid %s before filesystem/process access',async(option,value)=>{
  const directory=await fixture();const args=['--receipt',path.join(directory,'main.json'),'--image',path.join(directory,'main.bin'),'--caller-rva','0x1000','--out',path.join(directory,'capture')];
  const index=args.indexOf(option);if(index<0)args.push(option,value);else args[index+1]=value;
  const result=await runProcess(process.env['WIREFIT_PYTHON']??'python',['-X','utf8','-I','-S',worker,...args],{cwd:directory,timeout_ms:10000});
  expect(result.code).toBe(1);expect(JSON.parse(result.stdout).error.code).toBe('INVALID_ARGUMENTS');expect(await readdir(directory)).toEqual([]);
 });
 it('derives signed CALL destinations from observed flat RVA bytes and rejects unobserved callers',async()=>{
  const directory=await fixture();const code=load+"\nimport struct\nimage=b'\\xe8'+struct.pack('<i',-0x105)+b'\\x90';result=ns['derive_call_target'](image,0x400000,0,[(0,6)])\ntry:ns['derive_call_target'](image,0x400000,0,[(0,4)])\nexcept Exception as error:failure=error.code\nprint(json.dumps({'target':result['target_va'],'failure':failure}))";
  const result=await python(code,directory);expect(result.code,result.stderr).toBe(0);expect(JSON.parse(result.stdout)).toEqual({target:'0x3fff00',failure:'UNOBSERVED_CALLER'});
 });
 it.each([[0x400000,0x100,'0x400105'],[0xfffffff0,0x100,'CALL_TARGET_OVERFLOW'],[1,-100,'CALL_TARGET_OVERFLOW']])('bounds the rel32 target derived from base %s displacement %s',async(base,displacement,expected)=>{
  const directory=await fixture();const code=load+"\nimport struct\nimage=b'\\xe8'+struct.pack('<i',int(sys.argv[3]))+b'\\x90'\ntry:result=ns['derive_call_target'](image,int(sys.argv[2]),0,[(0,6)])['target_va']\nexcept Exception as error:result=error.code\nprint(json.dumps({'result':result}))";
  const execution=await python(code,directory,[String(base),String(displacement)]);expect(execution.code,execution.stderr).toBe(0);expect(JSON.parse(execution.stdout).result).toBe(expected);
 });
 it.each(['image_sha','coverage_sha','source_sha','not_call'])('does not open a process when %s validation fails',async(mode)=>{
  const directory=await fixture();const code=load+sourceFixture+`
mode=sys.argv[2]
if mode=='image_sha':receipt['image']['sha256']='0'*64
if mode=='coverage_sha':receipt['coverage']['pages'][0]['observed_sha256']='0'*64
if mode=='source_sha':receipt['source']['sha256']='0'*64
if mode=='not_call':image[4096]=0x90;image_path.write_bytes(image);receipt['image']['sha256']=hashlib.sha256(image).hexdigest();receipt['coverage']['pages'][0]['observed_sha256']=hashlib.sha256(image).hexdigest()
save_receipt();result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'result':result,'opened':Reader.opened}))`;
  const execution=await python(code,directory,[mode]);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);expect(result.result.status).toBe('failed');expect(result.opened).toBe(0);expect(await readdir(directory)).not.toContain('capture.json');
 });
 it.each(['changed','guard'])('keeps %s callers unknown without any private memory read',async(mode)=>{
  const directory=await fixture();const code=load+sourceFixture+"\nReader.mode=sys.argv[2];result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'result':result,'private_reads':Reader.private_reads,'queries':Reader.query_addresses}))";
  const execution=await python(code,directory,[mode]);expect(execution.code,execution.stderr).toBe(0);const wrapper=JSON.parse(execution.stdout);
  expect(wrapper.result.status).toBe('partial');expect(wrapper.result.callers[0].status).toBe('unknown');expect(wrapper.private_reads).toBe(0);expect(wrapper.result.captures).toEqual([]);
  if(mode==='changed')expect(wrapper.queries.every((address:number)=>0x400000<=address&&address<0x402000)).toBe(true);
  expect(JSON.parse(await readFile(path.join(directory,'capture.json'),'utf8')).status).toBe('partial');
 });
 it('deduplicates allocations, prioritizes target regions and records data regions independently',async()=>{
  const directory=await fixture();const code=load+sourceFixture+"\nargs+=['--caller-rva','0x1010'];result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps(result))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('completed');expect(result.allocations).toHaveLength(1);expect(result.allocations[0].metadata_scan_complete).toBe(true);expect(result.captures).toHaveLength(2);
  expect(result.captures[0].base).toBe('0x100000');expect(result.captures.reduce((sum:number,item:{size_bytes:number})=>sum+item.size_bytes,0)).toBe(8192);
  expect(result.allocations[0].regions.some((item:{capture_reason:string})=>item.capture_reason==='NOT_EXECUTABLE')).toBe(true);
  expect(result.callers.map((item:{status:string})=>item.status)).toEqual(['captured','captured']);
  const bytes=await readFile(path.join(directory,result.captures[0].file));expect(createHash('sha256').update(bytes).digest('hex')).toBe(result.captures[0].sha256);expect(result.cleanup.process_handle_closed).toBe(true);
 });
 it('retains initial partial bytes and explicit gaps in region coverage',async()=>{
  const directory=await fixture();const code=load+sourceFixture+"\nReader.mode='partial';result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps(result))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('partial');expect(result.captures[0].coverage.observed_bytes).toBe(100);expect(result.captures[0].coverage.unobserved_bytes).toBe(3996);
  const bytes=await readFile(path.join(directory,result.captures[0].file));expect(bytes.subarray(0,100)).toEqual(Buffer.alloc(100,65));expect(bytes.subarray(100)).toEqual(Buffer.alloc(3996));
 });
 it('bounds huge metadata regions without implying that the target was captured',async()=>{
  const directory=await fixture();const code=load+sourceFixture+"\nReader.query=lambda self,address:region(0x100000,size=32*1024*1024);result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'result':result,'private_reads':Reader.private_reads}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const wrapper=JSON.parse(execution.stdout);
  expect(wrapper.result.status).toBe('partial');expect(wrapper.result.allocations[0].metadata_scan_complete).toBe(false);expect(wrapper.result.callers[0].status).toBe('unknown');expect(wrapper.result.captures).toEqual([]);expect(wrapper.private_reads).toBe(0);
 });
 it('refuses a new RPM when attributes change before retry while preserving the initial prefix',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
Reader.mode='partial';old_query=Reader.query;old_read=Reader.read;addresses=[]
def query(self,address):
 if address==0x100000 and addresses.count(address):return region(0x100000,protect=0x120)
 return old_query(self,address)
def read(self,address,length):
 addresses.append(address);return old_read(self,address,length)
Reader.query=query;Reader.read=read
result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'result':result,'target_reads':addresses.count(0x100000)}))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const wrapper=JSON.parse(execution.stdout);
  expect(wrapper.target_reads).toBe(1);expect(wrapper.result.status).toBe('partial');expect(wrapper.result.captures[0].coverage.observed_bytes).toBe(100);expect(wrapper.result.captures[0].error.code).toBe('REGION_CHANGED');
  expect((await readFile(path.join(directory,wrapper.result.captures[0].file))).subarray(0,100)).toEqual(Buffer.alloc(100,65));
 });
 it('accepts normal VirtualQueryEx suffix metadata while reading a region larger than one chunk',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
def query(self,address):
 if 0x400000<=address<0x402000:return region(0x400000,size=8192,allocation=0x400000,kind=0x1000000)
 if 0x100000<=address<0x120000:
  base=address//4096*4096;return region(base,size=0x120000-base)
 return region(0x120000,state=0x10000,allocation=0,kind=0,protect=0)
Reader.query=query;result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'status':result['status'],'totals':result['totals'],'capture':result['captures'][0]}))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('completed');expect(result.capture.coverage.observed_bytes).toBe(131072);expect(result.capture.coverage.unobserved_bytes).toBe(0);expect(result.totals.observed_bytes).toBe(131072);
 });
 it('preserves captured files and failed receipt when the final identity check fails',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
def identity(self):
 if Reader.private_reads>=2:raise ns['CaptureError']('PROCESS_IDENTITY_FAILED','synthetic late identity error')
 return dict(endpoint)
Reader.identity=identity
result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps(result))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('failed');expect(result.identity.end_error.code).toBe('PROCESS_IDENTITY_FAILED');expect(result.captures).toHaveLength(2);expect(result.cleanup.process_handle_closed).toBe(true);
  const bytes=await readFile(path.join(directory,result.captures[0].file));expect(createHash('sha256').update(bytes).digest('hex')).toBe(result.captures[0].sha256);expect(JSON.parse(await readFile(path.join(directory,'capture.json'),'utf8')).status).toBe('failed');
 });
 it('fails immediately on a transient identity contradiction even if the terminal check recovers',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
Reader.contradicted=False
def identity(self):
 value=dict(endpoint)
 if Reader.private_reads==1 and not Reader.contradicted:Reader.contradicted=True;value['creation_filetime']='9999'
 return value
Reader.identity=identity
result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'result':result,'reads':Reader.private_reads}))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const wrapper=JSON.parse(execution.stdout),result=wrapper.result;
  expect(result.status).toBe('failed');expect(result.error.code).toBe('PROCESS_IDENTITY_MISMATCH');expect(result.captures[0].coverage.observed_bytes).toBe(4096);expect(wrapper.reads).toBe(1);expect(result.identity.end.creation_filetime).toBe('1234');expect(result.cleanup.process_handle_closed).toBe(true);
 });
 it('marks the region failed when output hashing fails after a successful byte read',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
load_support=ns['load_support']
def support():
 value=load_support();old_hash=value.file_hash
 def digest(file):
  if str(file.name).endswith('-002.bin'):raise OSError('synthetic hash I/O failure')
  return old_hash(file)
 value.file_hash=digest;return value
ns['load_support']=support
print(json.dumps(ns['capture_private_regions'](ns['parse_arguments'](args))))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('failed');expect(result.captures[0].status).toBe('completed');expect(result.captures[1].status).toBe('failed');expect(result.captures[1].error.code).toBe('OUTPUT_FINALIZE_FAILED');expect(result.captures[1].sha256).toBe(null);
 });
 it('enforces the 16MiB byte budget across allocations without resetting it for duplicate callers',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
for rva,target in [(4096,0x2000000),(4112,0x4000000),(4128,0x6000000),(4144,0x2000010)]:image[rva:rva+6]=b'\\xe8'+struct.pack('<i',target-(0x400000+rva+5))+b'\\x90'
image_path.write_bytes(image);receipt['image']['sha256']=receipt['coverage']['pages'][0]['observed_sha256']=hashlib.sha256(image).hexdigest();save_receipt()
def query(self,address):
 if 0x400000<=address<0x402000:return region(0x400000,size=8192,allocation=0x400000,kind=0x1000000)
 for base in [0x2000000,0x4000000,0x6000000]:
  if base<=address<base+8*1024*1024:return region(base,size=8*1024*1024,allocation=base)
  if address==base+8*1024*1024:return region(address,state=0x10000,allocation=0,kind=0,protect=0)
 raise RuntimeError('unexpected synthetic query')
Reader.query=query;args+=['--caller-rva','0x1010','--caller-rva','0x1020','--caller-rva','0x1030']
result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'status':result['status'],'totals':result['totals'],'captures':len(result['captures']),'allocations':len(result['allocations']),'callers':[item['status'] for item in result['callers']]}))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);
  expect(result.status).toBe('partial');expect(result.totals.capture_file_bytes).toBe(16*1024*1024);expect(result.captures).toBe(2);expect(result.allocations).toBe(3);expect(result.callers).toEqual(['captured','captured','unknown','captured']);
 });
 it('enforces the global metadata query budget across callers and allocation scans',async()=>{
  const directory=await fixture();const code=load+sourceFixture+`
for rva,target in [(4096,0x2000000),(4112,0x2000010)]:image[rva:rva+6]=b'\\xe8'+struct.pack('<i',target-(0x400000+rva+5))+b'\\x90'
image_path.write_bytes(image);receipt['image']['sha256']=receipt['coverage']['pages'][0]['observed_sha256']=hashlib.sha256(image).hexdigest();save_receipt()
def query(self,address):
 if 0x400000<=address<0x402000:return region(0x400000,size=8192,allocation=0x400000,kind=0x1000000)
 base=address//4096*4096;return region(base,allocation=0x2000000,protect=0x20 if base==0x2000000 else 0x04)
Reader.query=query;args+=['--caller-rva','0x1010'];result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'status':result['status'],'queries':result['totals']['query_count'],'closed':result['allocations'][0]['metadata_scan_complete'],'private_reads':Reader.private_reads}))`;
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);expect(result).toEqual({status:'partial',queries:4096,closed:false,private_reads:0});
 });
 it('refuses a preexisting output prefix before opening a process',async()=>{
  const directory=await fixture();const code=load+sourceFixture+"\nPath('capture-001.bin').write_bytes(b'existing evidence');result=ns['capture_private_regions'](ns['parse_arguments'](args));print(json.dumps({'result':result,'opened':Reader.opened,'existing':Path('capture-001.bin').read_bytes().decode('ascii')}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);expect(result.opened).toBe(0);expect(result.result.error.code).toBe('OUTPUT_EXISTS');expect(result.existing).toBe('existing evidence');expect(await readdir(directory)).not.toContain('capture.json');
 });
 it.each([{base_address:0x100000,region_size:0},{base_address:0x100001,region_size:4096},{base_address:0xfffff000,region_size:8192}])('rejects malformed or overflowing VirtualQueryEx extents (%j)',async(overrides)=>{
  const directory=await fixture();const code=load+sourceFixture+"\nvalue=region(0x100000);value.update(json.loads(sys.argv[2]))\ntry:ns['validate_region'](value,0x100000,32)\nexcept Exception as error:print(json.dumps({'code':error.code}))";
  const execution=await python(code,directory,[JSON.stringify(overrides)]);expect(execution.code,execution.stderr).toBe(0);expect(JSON.parse(execution.stdout)).toEqual({code:'INVALID_QUERY_RESULT'});
 });
 it.skipIf(process.platform!=='win32')('queries and reads only the current Python test process using a native MBI buffer',async()=>{
  const directory=await fixture();const code=load+"\nimport os,ctypes\nvalue=ctypes.create_string_buffer(b'own-test-data')\nwith ns['WindowsRegionReader'](os.getpid(),address_bits=ctypes.sizeof(ctypes.c_void_p)*8) as reader:\n identity=reader.identity();address=ctypes.addressof(value);region=reader.query(address);read=reader.read(address,13)\nprint(json.dumps({'identity':identity,'region':region,'hex':read['data'].hex(),'expected_size':ctypes.sizeof(ns['MEMORY_BASIC_INFORMATION'])}))";
  const execution=await python(code,directory);expect(execution.code,execution.stderr).toBe(0);const result=JSON.parse(execution.stdout);expect(result.hex).toBe(Buffer.from('own-test-data').toString('hex'));expect(result.region.returned_size).toBe(result.expected_size);expect(result.region.region_size).toBeGreaterThan(0);expect(typeof result.identity.creation_filetime).toBe('string');expect(await readdir(directory)).toEqual([]);
 });
});
