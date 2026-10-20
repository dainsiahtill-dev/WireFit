import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,mkdir,writeFile,readdir,rm,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
const HERE=path.dirname(fileURLToPath(import.meta.url));
const ROOT=path.resolve(HERE,'../..');
const SOURCE=path.join(ROOT,'exports/vmde-20261020/unpacked_vmde.exe');
const ownedTemporaryFixtures=new Set();
async function temporaryFixture(){const folder=await mkdtemp(path.join(path.resolve(tmpdir()),'wirefit-startup-'));ownedTemporaryFixtures.add(path.resolve(folder));return folder;}
async function removeTemporaryFixture(folder){
 const selected=path.resolve(folder),base=path.resolve(tmpdir()),relative=path.relative(base,selected);
 assert.ok(relative!==''&&!path.isAbsolute(relative)&&relative.split(path.sep).every(part=>part!=='..')&&path.dirname(selected)===base&&path.basename(selected).startsWith('wirefit-startup-')&&ownedTemporaryFixtures.has(selected),'Refusing unowned/outside temporary fixture cleanup');
 await rm(selected,{recursive:true,force:true});ownedTemporaryFixtures.delete(selected);
}
async function patcher(){const selected=path.join(HERE,'patch.mjs');await assert.doesNotReject(lstat(selected),'Compatibility startup patcher is not implemented');return import(new URL('./patch.mjs',import.meta.url));}
let sourcePromise;
const source=()=>sourcePromise??=readFile(SOURCE);
function fixture(){
 const b=Buffer.alloc(0x800),pe=0x80,opt=pe+24; b.write('MZ',0,'ascii');b.writeUInt32LE(pe,0x3c);b.write('PE\0\0',pe,'ascii');
 b.writeUInt16LE(0x14c,pe+4);b.writeUInt16LE(1,pe+6);b.writeUInt16LE(0xe0,pe+20);b.writeUInt16LE(0x10f,pe+22);
 b.writeUInt16LE(0x10b,opt);b.writeUInt32LE(0x1100,opt+16);b.writeUInt32LE(0x400000,opt+28);
 b.writeUInt32LE(0x1000,opt+32);b.writeUInt32LE(0x200,opt+36);b.writeUInt32LE(0x2000,opt+56);b.writeUInt32LE(0x400,opt+60);
 b.writeUInt32LE(16,opt+92);b.writeUInt32LE(0x1000,opt+104);b.writeUInt32LE(40,opt+108);
 const section=opt+0xe0;b.write('.idata',section,'ascii');b.writeUInt32LE(0x400,section+8);b.writeUInt32LE(0x1000,section+12);
 b.writeUInt32LE(0x400,section+16);b.writeUInt32LE(0x400,section+20);b.writeUInt32LE(0xc0000040,section+36);
 b.writeUInt32LE(0x1100,0x400);b.writeUInt32LE(0x1080,0x40c);b.writeUInt32LE(0x1120,0x410);
 b.write('KeRnEl32.DlL\0',0x480,'ascii');b.writeUInt32LE(0x1140,0x500);b.writeUInt32LE(0x1140,0x520);
 b.write('GetModuleHandleA\0',0x542,'ascii');return b;
}
test('bounded slot parser resolves OFT and actual FT VA from mixed-case library',async()=>{
 const m=await patcher();const rows=m.parseImportSlots(fixture());assert.equal(rows.length,1);assert.equal(rows[0].symbol,'GetModuleHandleA');
 assert.equal(rows[0].lookup_rva,0x1100);assert.equal(rows[0].iat_rva,0x1120);assert.equal(rows[0].iat_va,0x401120);
 assert.equal(m.resolveGetModuleHandleSlot(fixture()).iat_va,0x401120);
});
test('public parser rejects undersized or over64MiB input before owning a copy',async()=>{const m=await patcher();assert.throws(()=>m.parseImportSlots(new Uint8Array(63)),/input length/i);assert.throws(()=>m.parseImportSlots(new Uint8Array(64*1024*1024+1)),/input length/i);});
test('unbound OFT-zero imports resolve through FT instead',async()=>{const m=await patcher(),b=fixture();b.writeUInt32LE(0,0x400);assert.equal(m.resolveGetModuleHandleSlot(b).lookup_rva,0x1120);});
test('duplicate target descriptors are rejected even when they name the same slot',async()=>{const m=await patcher(),b=fixture();b.copy(b,0x414,0x400,0x414);b.writeUInt32LE(60,0x98+108);assert.throws(()=>m.resolveGetModuleHandleSlot(b),/unique/i);});
test('ordinal imports do not impersonate GetModuleHandleA',async()=>{const m=await patcher(),b=fixture();b.writeUInt32LE(0x80000001,0x500);assert.equal(m.parseImportSlots(b)[0].ordinal,1);assert.throws(()=>m.resolveGetModuleHandleSlot(b),/unique/i);});
test('directory without bounded null descriptor is rejected',async()=>{const m=await patcher(),b=fixture();b.writeUInt32LE(20,0x98+108);assert.throws(()=>m.parseImportSlots(b),/terminat/i);});
test('unmapped and oversized import-name RVAs are rejected',async()=>{const m=await patcher();for(const rva of [0x2000,0x7ffffffe]){const b=fixture();b.writeUInt32LE(rva,0x500);assert.throws(()=>m.parseImportSlots(b),/map|range|bound/i);}});
test('separate OFT termination bounds loader slots without inventing a zero FT successor',async()=>{const m=await patcher(),b=fixture();b.writeUInt32LE(0xffffffff,0x524);assert.equal(m.parseImportSlots(b).length,1);});
test('non-ASCII and unbounded import strings are rejected',async()=>{const m=await patcher();const bad=fixture();bad[0x480]=0x80;assert.throws(()=>m.parseImportSlots(bad),/ASCII/i);const long=fixture();long.fill(0x41,0x542);assert.throws(()=>m.parseImportSlots(long),/terminat|budget|length/i);});
test('overlapping virtual section mappings are rejected',async()=>{const m=await patcher(),b=fixture(),section=0x98+0xe0;b.writeUInt16LE(2,0x86);b.copy(b,section+40,section,section+40);assert.throws(()=>m.parseImportSlots(b),/overlap|ambig|unique/i);});
test('truncated raw section and malformed PE bounds are rejected',async()=>{const m=await patcher(),b=fixture();b.writeUInt32LE(0x1000,0x98+0xe0+16);assert.throws(()=>m.parseImportSlots(b),/raw|range|trunc/i);assert.throws(()=>m.parseImportSlots(Buffer.from('MZ','ascii')));});
test('bound imports cannot use FT as a name table when OFT is absent',async()=>{const m=await patcher(),b=fixture();b.writeUInt32LE(0,0x400);b.writeUInt32LE(123,0x404);assert.throws(()=>m.parseImportSlots(b),/bound|OriginalFirstThunk/i);});
test('fixed source patches an independent copy and only the 54 allowed bytes',async()=>{
 const m=await patcher(),b=await source(),before=Buffer.from(b),r=m.patchCompatibilityStartup(b);
 assert.notEqual(r.bytes,b);assert.deepEqual(b,before);assert.equal(r.bytes.length,b.length);assert.equal(r.patches.length,2);
 const allowed=new Set(r.patches.flatMap(p=>Array.from({length:p.size_bytes},(_,i)=>p.file_offset+i)));assert.equal(allowed.size,54);
 let changed=0;for(let i=0;i<b.length;i++){if(b[i]!==r.bytes[i]){assert.ok(allowed.has(i));changed++;}}assert.ok(changed>35);
 assert.equal(Buffer.from(r.bytes).readUInt32LE(0x140),0xb0f64);assert.equal(r.assumptions.original_prefix_restored,false);assert.equal(r.assumptions.oep_identified,false);assert.equal(r.assumptions.runnable_verified,false);
});
test('exact stub initializes DF and zero quote-state with bounded rel32 targets',async()=>{
 const m=await patcher(),r=m.patchCompatibilityStartup(await source()),p=r.patches.find(p=>p.kind==='compatibility_prefix'),b=Buffer.from(r.bytes).subarray(p.file_offset,p.file_offset+50);
 assert.equal(b.subarray(0,8).toString('hex'),'fc6a7468b8028e00');assert.equal(b[8],0xe8);assert.equal(0x4b0f64+13+b.readInt32LE(9),0x4b12bc);
 assert.equal(b.subarray(13,20).toString('hex'),'33db895de08b3d');assert.equal(b.readUInt32LE(20),r.import_resolution.iat_va);
 assert.equal(b.subarray(24,36).toString('hex'),'53ffd78b483c03c80fb74118');assert.equal(b[36],0xe9);assert.equal(0x4b0f64+41+b.readInt32LE(37),0x4b0f96);assert.deepEqual(b.subarray(41),Buffer.alloc(9,0xcc));
 assert.equal(r.validation.stub_size_bytes,41);assert.match(r.assumptions.direction_flag_initialization,/CLD/);
});
test('body/helper/table/header assumptions are pinned and remain unchanged',async()=>{
 const m=await patcher(),b=await source(),r=m.patchCompatibilityStartup(b);assert.equal(r.assumptions.image_base,'0x400000');assert.equal(r.assumptions.dynamic_base,false);assert.equal(r.assumptions.relocations_stripped,true);
 for(const region of r.validation.regions.filter(p=>p.kind!=='original_prefix'&&p.kind!=='headers'))assert.deepEqual(r.bytes.subarray(region.file_offset,region.file_offset+region.size_bytes),new Uint8Array(b.subarray(region.file_offset,region.file_offset+region.size_bytes)));
 assert.equal(r.validation.original_entry_rva,0xb12bc);assert.ok(r.validation.pe_diagnostics.some(d=>d.code==='TLS_DIRECTORY_INVALID'));
});
test('wrong fixed source SHA and input type are rejected without mutation',async()=>{const m=await patcher(),b=Buffer.from(await source());b[0x200]^=1;const before=Buffer.from(b);assert.throws(()=>m.patchCompatibilityStartup(b),/source identity/i);assert.deepEqual(b,before);assert.throws(()=>m.patchCompatibilityStartup([1,2,3]),/Uint8Array/i);});
async function cli(args){return new Promise((resolve,reject)=>{const child=spawn(process.execPath,[path.join(HERE,'build.mjs'),...args],{cwd:ROOT,env:{...process.env,NODE_OPTIONS:'',NODE_PATH:''},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);const timer=setTimeout(()=>child.kill(),10000);child.on('error',reject);child.on('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,stdout,stderr});});});}
test('real CLI invalid fixed source leaves new output absent',async()=>{await patcher();const folder=await temporaryFixture();try{const input=path.join(folder,'invalid.bin'),out=path.join(folder,'out');await writeFile(input,Buffer.from('not the source','utf8'));const r=await cli(['--input',input,'--out',out]);assert.equal(r.code,1);const receipt=JSON.parse(r.stdout);assert.equal(receipt.status,'failed');assert.match(receipt.error.message,/source identity/i);await assert.rejects(lstat(out),{code:'ENOENT'});assert.equal(r.stderr,'');}finally{await removeTemporaryFixture(folder);}});
test('real CLI existing out and unsafe duplicate arguments preserve original files',async()=>{await patcher();const folder=await temporaryFixture();try{const out=path.join(folder,'out');await mkdir(out);await writeFile(path.join(out,'sentinel'),Buffer.from('original','utf8'));const r=await cli(['--input',SOURCE,'--out',out]);assert.equal(r.code,1);assert.match(JSON.parse(r.stdout).error.message,/already exists/i);assert.deepEqual(await readdir(out),['sentinel']);assert.equal(await readFile(path.join(out,'sentinel'),'utf8'),'original');const dup=await cli(['--input',SOURCE,'--input',SOURCE,'--out',out]);assert.equal(dup.code,1);assert.match(JSON.parse(dup.stdout).error.message,/repeat|duplicate/i);}finally{await removeTemporaryFixture(folder);}});
test('temporary cleanup rejects outside and unowned resolved paths before deletion',async()=>{await assert.rejects(removeTemporaryFixture(ROOT),/Refusing/);await assert.rejects(removeTemporaryFixture(tmpdir()),/Refusing/);await assert.rejects(removeTemporaryFixture(path.join(tmpdir(),'wirefit-startup-not-created-by-this-test')),/Refusing/);});
