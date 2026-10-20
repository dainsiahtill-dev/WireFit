import {createHash} from 'node:crypto';
import {inspectPe} from '../../dist/src/pe.js';

export const SOURCE_SHA256='50b6bb68637b23d14ee1886ca1e84d944fade255204e70a831f27a3ef4fd6992';
export const SOURCE_SIZE=14454272;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const need=(condition,message)=>{if(!condition)throw new Error(message);};
const hex=value=>'0x'+value.toString(16);
const LIMIT32=0x100000000;
const MAX_DESCRIPTORS=1024,MAX_SYMBOLS=8192,MAX_STRING=512,MAX_STRING_TOTAL=1024*1024;
const REGIONS=[
 {kind:'headers',rva:0,size_bytes:1024,sha256:'27a1546ba196204cb57dd6715a58cb6b13e60ee28d49e521d13392c4b74c796b'},
 {kind:'original_prefix',rva:0xb0f64,size_bytes:50,sha256:'98039dc27a9ff31c226094c40edc84d71989c5f2c925354bd06f2adc7d50b9e1'},
 {kind:'decoded_crt_body',rva:0xb0f96,size_bytes:464,sha256:'12f62330cc25898b88f213a8bc08131957b908eccb9d6b19be7ba1f8aa9b2e48'},
 {kind:'frame_helper',rva:0xb12bc,size_bytes:59,sha256:'dc2d38b7225847dfeae3bcfc949f506480796a8284dc8e45ae9d789986f05af2'},
 {kind:'scope_table',rva:0x4e02b8,size_bytes:32,sha256:'59fe68492490219db6f41d3e01a21b2e1c8b97b7bb4e32ebaf8d90422a02c681'}
];

function layout(input){
 need(input instanceof Uint8Array,'PE input must be a Uint8Array');
 need(input.byteLength>=64&&input.byteLength<=64*1024*1024,'PE parser input length must be 64 bytes through 64 MiB');
 const bytes=new Uint8Array(input),inspection=inspectPe(bytes),view=new DataView(bytes.buffer);
 const pe=view.getUint32(0x3c,true),optional=pe+24,optionalSize=view.getUint16(pe+20,true);
 need(inspection.format==='PE32'&&view.getUint16(pe+4,true)===0x14c,'Only PE32 I386 input is supported');
 const structural=inspection.diagnostics.find(d=>/^(HEADER_SIZE_INVALID|SECTION_RAW_TRUNCATED|SECTION_VIRTUAL_RANGE_INVALID|SECTION_VIRTUAL_OVERLAP)$/.test(d.code));
 need(!structural,'Ambiguous/truncated PE mapping: '+(structural?.message??''));
 const imageBase=view.getUint32(optional+28,true),imageSize=view.getUint32(optional+56,true),headersSize=view.getUint32(optional+60,true);
 const sections=inspection.sections;
 for(let i=0;i<sections.length;i++){
  const a=sections[i];need(a.raw_size===0||a.raw_offset>=headersSize,'Section raw data overlaps headers');
  for(let j=i+1;j<sections.length;j++){const b=sections[j];need(!a.raw_size||!b.raw_size||a.raw_offset+a.raw_size<=b.raw_offset||b.raw_offset+b.raw_size<=a.raw_offset,'Sections have overlapping raw ranges');}
 }
 const map=(rva,size=1)=>{
  need(Number.isSafeInteger(rva)&&Number.isSafeInteger(size)&&rva>=0&&size>0&&rva+size<=LIMIT32&&rva+size<=imageSize,'RVA range exceeds mapped image bounds');
  const end=rva+size,matching=sections.filter(s=>rva<s.rva+Math.max(s.virtual_size,s.raw_size)&&s.rva<end);
  const inHeaders=rva<headersSize;
  if(inHeaders){need(end<=headersSize&&matching.length===0,'Ambiguous header mapping');return {offset:rva,available:headersSize-rva};}
  need(matching.length===1,'RVA has no unique section mapping');const section=matching[0],delta=rva-section.rva;
  need(delta>=0&&delta+size<=section.raw_size&&section.raw_offset+delta+size<=bytes.length,'RVA is not fully file-backed');
  return {offset:section.raw_offset+delta,available:Math.min(section.raw_size-delta,imageSize-rva)};
 };
 return {bytes,view,inspection,pe,optional,optionalSize,imageBase,imageSize,headersSize,map};
}

function slotsFrom(image){
 const {bytes,view,optional,optionalSize,imageBase,map}=image;
 need(optionalSize>=112&&view.getUint32(optional+92,true)>=2,'Import data directory missing');
 const directoryRva=view.getUint32(optional+104,true),directorySize=view.getUint32(optional+108,true);
 need(directoryRva>0&&directorySize>=20&&directorySize<=MAX_DESCRIPTORS*20,'Import descriptor budget or bounds invalid');
 map(directoryRva,directorySize);
 const output=[];let symbols=0,stringBytes=0,terminated=false;
 const readAscii=rva=>{
  const {offset,available}=map(rva),bound=Math.min(available,MAX_STRING);let value='';
  for(let index=0;index<bound;index++){
   need(++stringBytes<=MAX_STRING_TOTAL,'Import ASCII string budget exceeded');const byte=bytes[offset+index];
   if(byte===0){need(value.length>0,'Empty import ASCII name');return value;}
   need(byte>=0x20&&byte<=0x7e,'Import name contains non-printable ASCII');value+=String.fromCharCode(byte);
  }
  throw new Error('Import string not terminated within mapping/length budget');
 };
 for(let index=0;index<Math.floor(directorySize/20);index++){
  need(index<MAX_DESCRIPTORS,'Import descriptor budget exceeded');const descriptorRva=directoryRva+20*index,offset=map(descriptorRva,20).offset;
  const fields=Array.from({length:5},(_,i)=>view.getUint32(offset+4*i,true));
  if(fields.every(x=>x===0)){terminated=true;break;}
  const [oft,timestamp,,nameRva,firstThunk]=fields;
  need(nameRva!==0&&firstThunk!==0,'Import descriptor missing name or FirstThunk');
  need(oft!==0||timestamp===0,'Bound import without OriginalFirstThunk cannot use FT names');
  const library=readAscii(nameRva),lookupBase=oft||firstThunk;let ended=false;
  for(let item=0;item<=MAX_SYMBOLS;item++){
   const lookupRva=lookupBase+4*item,iatRva=firstThunk+4*item;
   const lookupOffset=map(lookupRva,4).offset;
   const value=view.getUint32(lookupOffset,true);
   // OFT bounds how many corresponding loader slots are populated. A rebuilt
   // dump can retain unrelated data after that FT span; never scan FT values
   // as a second name list or require a fabricated extra terminator there.
   if(value===0){ended=true;break;}
   need(++symbols<=MAX_SYMBOLS,'Import symbol budget exceeded');
   const iatOffset=map(iatRva,4).offset;
   const row={library,descriptor_rva:descriptorRva,lookup_rva:lookupRva,iat_rva:iatRva,iat_va:imageBase+iatRva,iat_file_offset:iatOffset,lookup_source:oft?'OriginalFirstThunk':'FirstThunk_unbound'};
   need(row.iat_va+4<=LIMIT32,'IAT virtual address overflows PE32');
   if(value>=0x80000000){need((value&0x7fff0000)===0,'Ordinal thunk reserved bits invalid');row.ordinal=value&0xffff;}
   else {const hintOffset=map(value,2).offset;row.hint=view.getUint16(hintOffset,true);row.symbol=readAscii(value+2);}
   output.push(row);
  }
  need(ended,'Import thunk table not terminated within symbol budget');
 }
 need(terminated,'Import directory not terminated within descriptor bounds');return output;
}

/** Bounded raw-PE slot decoding only; it does not resolve or execute an API. */
export function parseImportSlots(input){return slotsFrom(layout(input));}
function uniqueSlot(rows){const matches=rows.filter(row=>row.library.toLowerCase()==='kernel32.dll'&&row.symbol==='GetModuleHandleA');need(matches.length===1,'Expected one unique kernel32!GetModuleHandleA import slot');return matches[0];}
export function resolveGetModuleHandleSlot(input){return uniqueSlot(parseImportSlots(input));}

function stub(iatVA){
 const bytes=Buffer.alloc(50,0xcc);Buffer.from('fc6a7468b8028e00e80000000033db895de08b3d0000000053ffd78b483c03c80fb74118e900000000','hex').copy(bytes);
 bytes.writeInt32LE(0x4b12bc-(0x4b0f64+13),9);bytes.writeUInt32LE(iatVA,20);bytes.writeInt32LE(0x4b0f96-(0x4b0f64+41),37);
 return bytes;
}

/** Immutable compatibility experiment; only the fixed analysis image is accepted. */
export function patchCompatibilityStartup(input){
 need(input instanceof Uint8Array,'Startup input must be a Uint8Array');
 need(input.byteLength===SOURCE_SIZE,'Fixed source identity mismatch');
 const owned=new Uint8Array(input);need(owned.length===SOURCE_SIZE&&digest(owned)===SOURCE_SHA256,'Fixed source identity mismatch');
 const image=layout(owned),{view,pe,optional,map,imageBase,inspection}=image;
 need(imageBase===0x400000,'Fixed-base compatibility startup requires ImageBase 0x400000');
 const coff=view.getUint16(pe+22,true),dll=view.getUint16(optional+70,true);
 const relocationRva=view.getUint32(optional+96+5*8,true),relocationSize=view.getUint32(optional+100+5*8,true);
 need((coff&1)!==0&&(dll&0x40)===0&&relocationRva===0&&relocationSize===0,'Fixed-base/relocation assumptions do not hold');
 need(view.getUint32(optional+16,true)===0xb12bc,'Old analysis-dump entry differs');
 const regions=REGIONS.map(region=>{const fileOffset=map(region.rva,region.size_bytes).offset,data=owned.subarray(fileOffset,fileOffset+region.size_bytes);need(digest(data)===region.sha256,'Pinned '+region.kind+' bytes differ');return {...region,file_offset:fileOffset,va:hex(imageBase+region.rva),bytes_hex:Buffer.from(data).toString('hex')};});
 const table=regions.find(r=>r.kind==='scope_table');const tableOffset=table.file_offset;
 need(view.getUint32(tableOffset,true)===0xffffffff&&view.getUint32(tableOffset+4,true)===0x4b112a&&view.getUint32(tableOffset+8,true)===0x4b113e,'Scope table DWORD assumptions differ');
 const importResolution=uniqueSlot(slotsFrom(image)),prefix=regions.find(r=>r.kind==='original_prefix'),bytes=new Uint8Array(owned);
 const replacements=[{kind:'entry_point',file_offset:optional+16,size_bytes:4,rva:null,va:null,after:Buffer.from([0x64,0x0f,0x0b,0])},
  {kind:'compatibility_prefix',file_offset:prefix.file_offset,size_bytes:50,rva:0xb0f64,va:'0x4b0f64',after:stub(importResolution.iat_va)}];
 need(replacements[0].file_offset+4<=replacements[1].file_offset,'Patch ranges overlap');
 const patches=replacements.map(row=>{
  const before=owned.subarray(row.file_offset,row.file_offset+row.size_bytes);bytes.set(row.after,row.file_offset);
  const {after,...metadata}=row;return {...metadata,before_hex:Buffer.from(before).toString('hex'),after_hex:after.toString('hex'),before_sha256:digest(before),after_sha256:digest(after)};
 });
 let changed=0;for(let index=0;index<bytes.length;index++)if(bytes[index]!==owned[index]){need(replacements.some(r=>r.file_offset<=index&&index<r.file_offset+r.size_bytes),'Unexpected byte mutation');changed++;}
 return {bytes,patches,import_resolution:importResolution,
  validation:{source_sha256:SOURCE_SHA256,size_bytes:SOURCE_SIZE,original_entry_rva:0xb12bc,new_entry_rva:0xb0f64,regions,changed_byte_count:changed,permitted_patch_bytes:54,pe_diagnostics:inspection.diagnostics,
   stub_size_bytes:41,padding_bytes:9,helper_call_target:'0x4b12bc',decoded_body_jump_target:'0x4b0f96',headers_unchanged_except_entry:true},
  assumptions:{kind:'experimental_compatibility_CRT_entry',original_prefix_restored:false,oep_identified:false,runnable_verified:false,
   image_base:'0x400000',dynamic_base:false,relocations_stripped:true,relocation_directory:{rva:0,size:0},
   local_allocation_bytes:0x74,scope_table_va:'0x8e02b8',quote_state:'EBX=0; DWORD[EBP-0x20]=0',
   direction_flag_initialization:'CLD at compatibility entry actively establishes DF=0; this is not an observed original-prefix instruction.',
   frame_constraint:'0x74 is conditional on the exact helper and unchanged observed saved-SP field; original prefix may perform other protection initialization.',
   imports:'GetModuleHandleA(NULL) is loaded from the unique loader IAT slot, never a captured heap thunk or system address.',
   unchanged_risks:['Existing TLS_DIRECTORY_INVALID is a strict file-backed inspector diagnostic, not proof of an OS loader failure: a virtual zero-fill template may be legal. Original protected/dump TLS directory semantics are not repaired by this builder.','This entry is a compatibility hypothesis, not an original-prefix/OEP reconstruction or whole-program equivalence proof.']}};
}
