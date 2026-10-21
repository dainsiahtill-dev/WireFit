/**
 * A bounded x86-32 interpreter.
 *
 * The interpreter exists so that a native function can be called from inside
 * WireFit instead of through a bespoke wrapper process. It is deliberately
 * small and explicit: it implements the integer 32-bit subset that recovered
 * kernels use, refuses everything else with a concrete fault, and never
 * executes native code.
 *
 * Every access is checked against a declared region and against the caller's
 * access policy, so an emulation run cannot read or write outside the
 * synthetic buffers it was given.
 */

export type RegisterName=
 | 'eax'|'ebx'|'ecx'|'edx'|'esi'|'edi'|'ebp'|'esp'|'eip'|'eflags';

export const REGISTER_NAMES:readonly RegisterName[]=[
 'eax','ebx','ecx','edx','esi','edi','ebp','esp','eip','eflags'];

export interface MemoryRegion{
 name:string;
 base:number;
 size_bytes:number;
 read:boolean;
 write:boolean;
 execute:boolean;
}

export interface AccessRange{ base:number; size_bytes:number; }

export type EmulationFaultCode=
 | 'EMULATION_UNSUPPORTED_OPCODE'
 | 'EMULATION_UNMAPPED_READ'
 | 'EMULATION_UNMAPPED_WRITE'
 | 'EMULATION_ACCESS_DENIED'
 | 'EMULATION_EXECUTION_DENIED'
 | 'EMULATION_BUDGET_EXHAUSTED'
 | 'EMULATION_INVALID_STATE'
 | 'EMULATION_FAULT';

export class EmulationFault extends Error{
 constructor(public readonly code:EmulationFaultCode,message:string,public readonly address:number|null=null){
  super(message);
  this.name='EmulationFault';
 }
}

export interface EmulationBudget{
 max_instructions:number;
 max_memory_bytes:number;
}

export interface EmulationResult{
 instructions_executed:number;
 visited_instructions:number;
 final_eip:number;
 final_esp:number;
 registers:Record<RegisterName,number>;
 fault:EmulationFault|null;
}

const PAGE_SIZE=4096;

function u32(value:number):number{return value>>>0;}
function s32(value:number):number{return value|0;}
function u8(value:number):number{return value&0xff;}
/** Sign extends an eight bit value to thirty two bits. */
function signExtend8(value:number):number{return (value<<24)>>24;}

/** A sparse, region-checked 32-bit address space. */
export class Memory{
 private readonly pages=new Map<number,Uint8Array>();
 private readonly regions:MemoryRegion[]=[];
 constructor(regions:readonly MemoryRegion[]){
  for(const region of regions)this.regions.push({...region});
  for(const region of this.regions){
   const first=Math.floor(region.base/PAGE_SIZE),
    last=Math.floor((region.base+region.size_bytes-1)/PAGE_SIZE);
   for(let index=first;index<=last;index++)
    if(!this.pages.has(index))this.pages.set(index,new Uint8Array(PAGE_SIZE));
  }
 }
 regionAt(address:number):MemoryRegion|null{
  for(const region of this.regions)
   if(address>=region.base&&address<region.base+region.size_bytes)return region;
  return null;
 }
 private page(address:number):Uint8Array{
  const index=Math.floor(address/PAGE_SIZE);
  const page=this.pages.get(index);
  if(page===undefined)throw new EmulationFault('EMULATION_UNMAPPED_READ','No page is mapped at 0x'+address.toString(16));
  return page;
 }
 read8(address:number):number{
  const region=this.regionAt(address);
  if(region===null||!region.read)
   throw new EmulationFault('EMULATION_UNMAPPED_READ','Read from an unmapped or unreadable address 0x'+address.toString(16),address);
  return this.page(address)[address%PAGE_SIZE]!;
 }
 write8(address:number,value:number):void{
  const region=this.regionAt(address);
  if(region===null||!region.write)
   throw new EmulationFault('EMULATION_UNMAPPED_WRITE','Write to an unmapped or unwritable address 0x'+address.toString(16),address);
  this.page(address)[address%PAGE_SIZE]=u8(value);
 }
 readBytes(address:number,length:number):Uint8Array{
  const out=new Uint8Array(length);
  for(let index=0;index<length;index++)out[index]=this.read8(address+index);
  return out;
 }
 writeBytes(address:number,bytes:Uint8Array):void{
  for(let index=0;index<bytes.length;index++)this.write8(address+index,bytes[index]!);
 }
 /**
  * Loads bytes into a region regardless of its write permission.
  *
  * This is the image loader's path: code and initial memory are placed
  * before the region permissions take effect, exactly like the read-only code
  * region of a real process image.
  */
 loadBytes(address:number,bytes:Uint8Array):void{
  for(let index=0;index<bytes.length;index++){
   const region=this.regionAt(address+index);
   if(region===null)throw new EmulationFault('EMULATION_UNMAPPED_WRITE','Load into an unmapped address 0x'+(address+index).toString(16),address+index);
   this.page(address+index)[(address+index)%PAGE_SIZE]=u8(bytes[index]!);
  }
 }
 read32(address:number):number{
  return u32(this.read8(address)|(this.read8(address+1)<<8)|(this.read8(address+2)<<16)|(this.read8(address+3)<<24));
 }
 write32(address:number,value:number):void{
  this.write8(address,value);
  this.write8(address+1,value>>>8);
  this.write8(address+2,value>>>16);
  this.write8(address+3,value>>>24);
 }
}

/** The interpreter state: registers and flags. */
export class Registers{
 eax=0;ebx=0;ecx=0;edx=0;esi=0;edi=0;ebp=0;esp=0;eip=0;
 /** Carry, parity, auxiliary carry, zero, sign, overflow, direction flag. */
 cf=false;pf=false;af=false;zf=false;sf=false;of=false;df=false;
 get(name:RegisterName):number{
  switch(name){
   case 'eax':return this.eax;case 'ebx':return this.ebx;case 'ecx':return this.ecx;case 'edx':return this.edx;
   case 'esi':return this.esi;case 'edi':return this.edi;case 'ebp':return this.ebp;case 'esp':return this.esp;
   case 'eip':return this.eip;default:return this.packedFlags();
  }
 }
 set(name:RegisterName,value:number):void{
  const v=u32(value);
  switch(name){
   case 'eax':this.eax=v;break;case 'ebx':this.ebx=v;break;case 'ecx':this.ecx=v;break;case 'edx':this.edx=v;break;
   case 'esi':this.esi=v;break;case 'edi':this.edi=v;break;case 'ebp':this.ebp=v;break;case 'esp':this.esp=v;break;
   case 'eip':this.eip=v;break;
   case 'eflags':this.unpackFlags(v);break;
  }
 }
 /** The packed EFLAGS value. */
 packedFlags():number{
  let value=0x2;
  if(this.cf)value|=0x001;
  if(this.pf)value|=0x004;
  if(this.af)value|=0x010;
  if(this.zf)value|=0x040;
  if(this.sf)value|=0x080;
  if(this.df)value|=0x400;
  if(this.of)value|=0x800;
  return value>>>0;
 }
 /** Restores the flags from a packed EFLAGS value. */
 unpackFlags(value:number):void{
  this.cf=(value&0x001)!==0;
  this.pf=(value&0x004)!==0;
  this.af=(value&0x010)!==0;
  this.zf=(value&0x040)!==0;
  this.sf=(value&0x080)!==0;
  this.df=(value&0x400)!==0;
  this.of=(value&0x800)!==0;
 }
 snapshot():Record<RegisterName,number>{
  return {eax:this.eax,ebx:this.ebx,ecx:this.ecx,edx:this.edx,esi:this.esi,edi:this.edi,ebp:this.ebp,esp:this.esp,eip:this.eip,eflags:this.packedFlags()};
 }
}

const CONDITION_CODES:{ cc:number; name:string }[]=[
 {cc:0x0,name:'o'},{cc:0x1,name:'no'},{cc:0x2,name:'b'},{cc:0x3,name:'ae'},
 {cc:0x4,name:'e'},{cc:0x5,name:'ne'},{cc:0x6,name:'be'},{cc:0x7,name:'a'},
 {cc:0x8,name:'s'},{cc:0x9,name:'ns'},{cc:0xa,name:'p'},{cc:0xb,name:'np'},
 {cc:0xc,name:'l'},{cc:0xd,name:'ge'},{cc:0xe,name:'le'},{cc:0xf,name:'g'}];

/** The interpreter itself. */
export class X86Interpreter{
 readonly memory:Memory;
 readonly registers=new Registers();
 private readonly budget:EmulationBudget;
 private readonly readable:AccessRange[];
 private readonly writable:AccessRange[];
 private readonly allowedStarts:ReadonlySet<number>|null;
 instructions=0;
 readonly visited=new Set<number>();
 constructor(options:{
  memory:Memory;
  budget:EmulationBudget;
  readable:readonly AccessRange[];
  writable:readonly AccessRange[];
  allowed_instruction_starts?:ReadonlySet<number>|null;
 }){
  this.memory=options.memory;
  this.budget=options.budget;
  this.readable=[...options.readable];
  this.writable=[...options.writable];
  this.allowedStarts=options.allowed_instruction_starts??null;
 }
 private checkRead(address:number,size:number):void{
  const region=this.memory.regionAt(address);
  if(region===null||!region.read)
   throw new EmulationFault('EMULATION_UNMAPPED_READ','Read from an unmapped or unreadable address 0x'+address.toString(16),address);
  if(this.readable.length>0&&!this.inRanges(this.readable,address,size))
   throw new EmulationFault('EMULATION_ACCESS_DENIED','Read outside the declared readable ranges at 0x'+address.toString(16),address);
 }
 private checkWrite(address:number,size:number):void{
  const region=this.memory.regionAt(address);
  if(region===null||!region.write)
   throw new EmulationFault('EMULATION_UNMAPPED_WRITE','Write to an unmapped or unwritable address 0x'+address.toString(16),address);
  if(this.writable.length>0&&!this.inRanges(this.writable,address,size))
   throw new EmulationFault('EMULATION_ACCESS_DENIED','Write outside the declared writable ranges at 0x'+address.toString(16),address);
 }
 private inRanges(ranges:readonly AccessRange[],address:number,size:number):boolean{
  for(const range of ranges)
   if(address>=range.base&&address+size<=range.base+range.size_bytes)return true;
  return false;
 }
 private read8(address:number):number{this.checkRead(address,1);return this.memory.read8(address);}
 private write8(address:number,value:number):void{this.checkWrite(address,1);this.memory.write8(address,value);}
 private read16(address:number):number{return u32(this.read8(address)|(this.read8(address+1)<<8));}
 private read32(address:number):number{
  this.checkRead(address,4);
  return u32(this.memory.read8(address)|(this.memory.read8(address+1)<<8)|(this.memory.read8(address+2)<<16)|(this.memory.read8(address+3)<<24));
 }
 private write16(address:number,value:number):void{this.write8(address,value);this.write8(address+1,value>>>8);}
 private write32(address:number,value:number):void{
  this.checkWrite(address,4);
  this.memory.write32(address,value);
 }
 private fetch8(address:number):number{
  const region=this.memory.regionAt(address);
  if(region===null||!region.execute)
   throw new EmulationFault('EMULATION_EXECUTION_DENIED','Execution outside an executable region at 0x'+address.toString(16),address);
  return this.memory.read8(address);
 }
 private fetch16(address:number):number{
  const region=this.memory.regionAt(address);
  if(region===null||!region.execute)
   throw new EmulationFault('EMULATION_EXECUTION_DENIED','Execution outside an executable region at 0x'+address.toString(16),address);
  return u32(this.memory.read8(address)|(this.memory.read8(address+1)<<8));
 }
 private fetch32(address:number):number{
  const region=this.memory.regionAt(address);
  if(region===null||!region.execute)
   throw new EmulationFault('EMULATION_EXECUTION_DENIED','Execution outside an executable region at 0x'+address.toString(16),address);
  return u32(this.memory.read8(address)|(this.memory.read8(address+1)<<8)|(this.memory.read8(address+2)<<16)|(this.memory.read8(address+3)<<24));
 }
 private push32(value:number):void{
  this.registers.esp=u32(this.registers.esp-4);
  this.write32(this.registers.esp,value);
 }
 private pop32():number{
  const value=this.read32(this.registers.esp);
  this.registers.esp=u32(this.registers.esp+4);
  return value;
 }
 private condition(code:number):boolean{
  const r=this.registers;
  switch(code){
   case 0x0:return r.of;case 0x1:return !r.of;
   case 0x2:return r.cf;case 0x3:return !r.cf;
   case 0x4:return r.zf;case 0x5:return !r.zf;
   case 0x6:return r.cf||r.zf;case 0x7:return !r.cf&&!r.zf;
   case 0x8:return r.sf;case 0x9:return !r.sf;
   case 0xa:return r.pf;case 0xb:return !r.pf;
   case 0xc:return r.sf!==r.of;case 0xd:return r.sf===r.of;
   case 0xe:return r.zf||(r.sf!==r.of);case 0xf:return !r.zf&&(r.sf===r.of);
   default:return false;
  }
 }
 private setFlagsLogic(result:number):void{
  const r=this.registers;
  r.cf=false;r.of=false;
  r.zf=u32(result)===0;
  r.sf=(u32(result)&0x80000000)!==0;
  r.pf=parity(u8(result));
  r.af=false;
 }
 private setFlagsAdd(a:number,b:number,carryIn:number):number{
  const r=this.registers;
  const wide=BigInt(u32(a))+BigInt(u32(b))+BigInt(carryIn);
  const result=u32(Number(wide));
  r.cf=wide>0xffffffffn;
  r.af=((u8(a)^u8(b)^u8(result))&0x10)!==0;
  r.zf=result===0;
  r.sf=(result&0x80000000)!==0;
  r.of=((~(u8(a)^u8(b))&(u8(a)^u8(result)))&0x80)!==0;
  r.pf=parity(u8(result));
  return result;
 }
 private setFlagsSub(a:number,b:number,borrowIn:number):number{
  const r=this.registers;
  const wide=BigInt(u32(a))-BigInt(u32(b))-BigInt(borrowIn);
  const result=u32(Number(wide));
  r.cf=wide<0n;
  r.af=((u8(a)^u8(b)^u8(result))&0x10)!==0;
  r.zf=result===0;
  r.sf=(result&0x80000000)!==0;
  r.of=(((u8(a)^u8(b))&(u8(a)^u8(result)))&0x80)!==0;
  r.pf=parity(u8(result));
  return result;
 }
 private setFlagsMultiply(result:number):void{
  const r=this.registers;
  r.cf=false;r.of=false;
  r.zf=u32(result)===0;
  r.sf=(u32(result)&0x80000000)!==0;
  r.pf=parity(u8(result));
 }
 private setFlagsShift(result:number,count:number):void{
  const r=this.registers;
  r.cf=count>0;
  r.of=false;
  r.zf=u32(result)===0;
  r.sf=(u32(result)&0x80000000)!==0;
  r.pf=parity(u8(result));
 }
 /** Executes one instruction and returns the next instruction pointer. */
 step():number{
  const r=this.registers;
  const eip=r.eip;
  if(this.allowedStarts!==null&&!this.allowedStarts.has(eip))
   throw new EmulationFault('EMULATION_ACCESS_DENIED','Execution left the verified instruction starts at 0x'+eip.toString(16),eip);
  if(this.instructions>=this.budget.max_instructions)
   throw new EmulationFault('EMULATION_BUDGET_EXHAUSTED','The instruction budget was exhausted',eip);
  const next=this.execute(eip);
  r.eip=next;
  this.instructions++;
  this.visited.add(eip);
  return next;
 }
 /** Runs until the stop address is reached or a fault occurs. */
 run(stopAddress:number):EmulationResult{
  const r=this.registers;
  let fault:EmulationFault|null=null;
  try{
   while(r.eip!==stopAddress){
    if(this.instructions>=this.budget.max_instructions)
     throw new EmulationFault('EMULATION_BUDGET_EXHAUSTED','The instruction budget was exhausted',r.eip);
    this.step();
   }
  }catch(error){
   if(error instanceof EmulationFault)fault=error;
   else throw error;
  }
  return {
   instructions_executed:this.instructions,
   visited_instructions:this.visited.size,
   final_eip:r.eip,
   final_esp:r.esp,
   registers:r.snapshot(),
   fault,
  };
 }
 private execute(eip:number):number{
  const r=this.registers;
  const opcode=this.fetch8(eip);
  if((globalThis as any).__DBG&&eip>=0x498bf0&&eip<=0x498c08)console.log('EXEC',eip.toString(16),'op',opcode.toString(16));
  let next=eip+1;
  switch(opcode){
   default:{
    // The ALU block 0x00..0x3F: the operation lives in opcode bits 3..5, the
    // direction in the low bit, and the operand size in bit 0 of the pair.
    if(opcode<=0x3f&&(opcode&0x07)<=0x05&&opcode!==0x0f&&opcode!==0x27&&opcode!==0x2f&&opcode!==0x37&&opcode!==0x3f){
     const operation=(opcode>>3)&0x07;
     const toMemory=(opcode&1)===0;
     const pair=opcode&0x07;
     // A compare computes the flags only; it never writes its operands.
     const compare=operation===7;
     if(pair===0||pair===1){
      const size=pair===0?1:4;
      const modrm=this.fetch8(next);next++;
      const rm=this.decodeModrm(modrm,next);next=rm.next;
      const result=this.alu(operation,this.readRm(rm,size),this.readReg(rm.reg,size),false);
      if(!compare){
       if(toMemory)this.writeRm(rm,result,size);
       else this.writeReg(rm.reg,result,size);
      }
      return next;
     }
     if(pair===2||pair===3){
      const size=pair===2?1:4;
      const modrm=this.fetch8(next);next++;
      const rm=this.decodeModrm(modrm,next);next=rm.next;
      // The destination is the register and the source is r/m, so the
      // subtraction order is register minus memory.
      const result=this.alu(operation,this.readReg(rm.reg,size),this.readRm(rm,size),false);
      if(!compare){
       if(toMemory)this.writeRm(rm,result,size);
       else this.writeReg(rm.reg,result,size);
      }
      return next;
     }
     // AL or EAX with an immediate.
     const size=pair===4?1:4;
     const immediate=size===4?this.fetch32(next):this.fetch8(next);
     next+=size;
     this.alu(operation,this.readReg(0,size),immediate,false);
     return next;
    }
    throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported opcode 0x'+opcode.toString(16),eip);
   }
   case 0x0f:{
    const second=this.fetch8(next);next++;
    return this.executeTwoByte(second,eip,next);
   }
   case 0x40:case 0x41:case 0x42:case 0x43:case 0x44:case 0x45:case 0x46:case 0x47:{
    const index=opcode&0x07;
    const value=this.readReg(index,4);
    const result=this.alu(0,value,1,false);
    this.writeReg(index,result,4);
    return next;
   }
   case 0x48:case 0x49:case 0x4a:case 0x4b:case 0x4c:case 0x4d:case 0x4e:case 0x4f:{
    const index=opcode&0x07;
    this.alu(5,this.readReg(index,4),1,false);
    return next;
   }
   case 0x50:case 0x51:case 0x52:case 0x53:case 0x54:case 0x55:case 0x56:case 0x57:{
    this.push32(this.readReg(opcode&0x07,4));
    return next;
   }
   case 0x58:case 0x59:case 0x5a:case 0x5b:case 0x5c:case 0x5d:case 0x5e:case 0x5f:{
    const value=this.pop32();
    this.writeReg(opcode&0x07,value,4);
    return next;
   }
   case 0x60:{ // PUSHA
    const sp=r.esp;
    for(const name of ['eax','ecx','edx','ebx','esp','ebp','esi','edi'] as RegisterName[])this.push32(this.readRegName(name,4));
    r.esp=sp;
    return next;
   }
   case 0x61:{ // POPA
    const sp=r.esp;
    const order:RegisterName[]=['edi','esi','ebp','esp','ebx','edx','ecx','eax'];
    const values=order.map(()=>this.pop32());
    order.forEach((name,index)=>{if(name!=='esp')this.writeRegName(name,values[index]!,4);});
    r.esp=sp;
    return next;
   }
   case 0x68:{
    const immediate=this.fetch32(next);next+=4;
    this.push32(immediate);
    return next;
   }
   case 0x6a:{
    const immediate=this.fetch8(next);next++;
    this.push32(s32(u8(immediate)));
    return next;
   }
   case 0x70:case 0x71:case 0x72:case 0x73:case 0x74:case 0x75:case 0x76:case 0x77:
   case 0x78:case 0x79:case 0x7a:case 0x7b:case 0x7c:case 0x7d:case 0x7e:case 0x7f:{
    const displacement=signExtend8(this.fetch8(next));next++;
    if(this.condition(opcode&0x0f))next=u32(next+displacement);
    return next;
   }
   case 0x80:case 0x81:case 0x83:{
    // The ALU operation of an immediate group is selected by the ModRM reg
    // field, not by the opcode bits.
    const modrm=this.fetch8(next);next++;
    const form=(modrm>>3)&0x07;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const immediate=opcode===0x81?this.fetch32(next):opcode===0x83?signExtend8(this.fetch8(next)):this.fetch8(next);
    next+=opcode===0x81?4:1;
    const result=this.alu(form,this.readRm(rm,4),immediate,false);
    this.writeRm(rm,result,4);
    return next;
   }
   case 0x84:case 0x85:{
    const size=opcode===0x85?4:1;
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const result=this.readRm(rm,size)&this.readReg(rm.reg,size);
    this.setFlagsLogic(result);
    return next;
   }
   case 0x86:case 0x87:{
    const size=opcode===0x87?4:1;
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const left=this.readRm(rm,size),right=this.readReg(rm.reg,size);
    this.writeRm(rm,right,size);
    this.writeReg(rm.reg,left,size);
    return next;
   }
   case 0x88:case 0x89:case 0x8a:case 0x8b:{
    const size=opcode===0x89||opcode===0x8b?4:1;
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const value=opcode===0x8a?this.readRm(rm,size):this.readRm(rm,size);
    if(opcode===0x88||opcode==0x89)this.writeRm(rm,this.readReg(rm.reg,size),size);
    else this.writeReg(rm.reg,value,size);
    return next;
   }
   case 0x8d:{
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    this.writeReg(rm.reg,rm.address!,4);
    return next;
   }
   case 0xf2:case 0xf3:{
    // A repeat prefix in front of a string instruction.
    const operation=this.fetch8(next);next++;
    const repeat=opcode===0xf3;
    const step=(address:number,delta:number):number=>this.registers.df?u32(address-delta):u32(address+delta);
    const once=():void=>{
     switch(operation){
      case 0xa4:{ // MOVSB
       const value=this.read8(this.registers.esi);
       this.write8(this.registers.edi,value);
       this.registers.esi=step(this.registers.esi,1);
       this.registers.edi=step(this.registers.edi,1);
       return;
      }
      case 0xa5:{ // MOVSD
       const value=this.read32(this.registers.esi);
       this.write32(this.registers.edi,value);
       this.registers.esi=step(this.registers.esi,4);
       this.registers.edi=step(this.registers.edi,4);
       return;
      }
      case 0xaa:{ // STOSB
       this.write8(this.registers.edi,this.registers.eax&0xff);
       this.registers.edi=step(this.registers.edi,1);
       return;
      }
      case 0xab:{ // STOSD
       this.write32(this.registers.edi,this.registers.eax);
       this.registers.edi=step(this.registers.edi,4);
       return;
      }
      case 0xac:{ // LODSB
       this.writeReg8(0,this.read8(this.registers.esi));
       this.registers.esi=step(this.registers.esi,1);
       return;
      }
      case 0xad:{ // LODSD
       this.writeReg(0,this.read32(this.registers.esi),4);
       this.registers.esi=step(this.registers.esi,4);
       return;
      }
      case 0xa6:{ // CMPSB
       const difference=this.read8(this.registers.esi)-this.read8(this.registers.edi);
       this.setFlagsSub(this.read8(this.registers.esi),this.read8(this.registers.edi),0);
       this.registers.esi=step(this.registers.esi,1);
       this.registers.edi=step(this.registers.edi,1);
       void difference;
       return;
      }
      case 0xa7:{ // CMPSD
       this.setFlagsSub(this.read32(this.registers.esi),this.read32(this.registers.edi),0);
       this.registers.esi=step(this.registers.esi,4);
       this.registers.edi=step(this.registers.edi,4);
       return;
      }
      case 0xae:{ // SCASB
       this.setFlagsSub(this.registers.eax&0xff,this.read8(this.registers.edi),0);
       this.registers.edi=step(this.registers.edi,1);
       return;
      }
      case 0xaf:{ // SCASD
       this.setFlagsSub(this.registers.eax,this.read32(this.registers.edi),0);
       this.registers.edi=step(this.registers.edi,4);
       return;
      }
      default:
       throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported string operation 0x'+operation.toString(16),eip);
     }
    };
    once();
    if(repeat){
     // A repeated string instruction decrements the counter and repeats while
     // the counter is not zero. Repeating the instruction, rather than
     // looping inside it, keeps the executed instruction sequence identical to
     // the hardware.
     this.registers.ecx=u32(this.registers.ecx-1);
     if(this.registers.ecx!==0)return eip;
    }
    return next;
   }
   case 0x90:{ // NOP
    return next;
   }
   case 0x98:{ // CWDE
    this.writeReg(0,s32(this.readReg(0,1)),4);
    return next;
   }
   case 0x99:{ // CDQ
    this.writeReg(2,this.readReg(0,4)<0?0xffffffff:0,4);
    return next;
   }
   case 0xa8:{
    const immediate=this.fetch8(next);next++;
    this.setFlagsLogic(this.readReg(0,1)&immediate);
    return next;
   }
   case 0xa9:{
    const immediate=this.fetch32(next);next+=4;
    this.setFlagsLogic(this.readReg(0,4)&immediate);
    return next;
   }
   case 0xb0:case 0xb1:case 0xb2:case 0xb3:case 0xb4:case 0xb5:case 0xb6:case 0xb7:{
    const immediate=this.fetch8(next);next++;
    this.writeReg8(opcode&0x07,immediate);
    return next;
   }
   case 0xb8:case 0xb9:case 0xba:case 0xbb:case 0xbc:case 0xbd:case 0xbe:case 0xbf:{
    const immediate=this.fetch32(next);next+=4;
    this.writeReg(opcode&0x07,immediate,4);
    return next;
   }
   case 0xc0:case 0xc1:{
    const size=opcode===0xc1?4:1;
    const modrm=this.fetch8(next);next++;
    const form=(modrm>>3)&0x07;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const count=this.fetch8(next);next++;
    this.writeRm(rm,this.shift(form,this.readRm(rm,size),count,size),size);
    return next;
   }
   case 0xc2:{
    const bytes=this.fetch16(next);next+=2;
    const target=this.pop32();
    r.esp=u32(r.esp+bytes);
    return target;
   }
   case 0xc3:{
    return this.pop32();
   }
   case 0xc6:case 0xc7:{
    const size=opcode===0xc7?4:1;
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const immediate=size===4?this.fetch32(next):this.fetch8(next);
    next+=size;
    this.writeRm(rm,immediate,size);
    return next;
   }
   case 0xc9:{ // LEAVE
    r.esp=r.ebp;
    r.ebp=this.pop32();
    return next;
   }
   case 0xcc:{
    throw new EmulationFault('EMULATION_FAULT','The emulated code reached an int 3 breakpoint',eip);
   }
   case 0xd1:case 0xd2:case 0xd3:{
    const size=opcode===0xd1?4:1;
    const modrm=this.fetch8(next);next++;
    const form=(modrm>>3)&0x07;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    const count=opcode===0xd1?1:this.readReg(1,1)&0xff;
    this.writeRm(rm,this.shift(form,this.readRm(rm,size),count,size),size);
    return next;
   }
   case 0xe8:{
    const displacement=s32(this.fetch32(next));next+=4;
    const target=u32(next+displacement);
    this.push32(next);
    return target;
   }
   case 0xe9:{
    const displacement=s32(this.fetch32(next));next+=4;
    return u32(next+displacement);
   }
   case 0xeb:{
    const displacement=signExtend8(this.fetch8(next));next++;
    return u32(next+displacement);
   }
   case 0xf6:case 0xf7:{
    const size=opcode===0xf7?4:1;
    const form=(this.fetch8(next)&0x38)>>3;next++;
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(modrm,next);next=rm.next;
    if(form===0||form===1){
     const immediate=size===4?this.fetch32(next):this.fetch8(next);
     next+=size;
     this.setFlagsLogic(this.readRm(rm,size)&immediate);
    }else if(form===2){ // NOT
     this.writeRm(rm,~this.readRm(rm,size),size);
    }else if(form===3){ // NEG
     const value=this.readRm(rm,size);
     const result=u32(-value);
     this.writeRm(rm,result,size);
     r.cf=value!==0;
     r.zf=result===0;
     r.sf=(result&0x80000000)!==0;
     r.of=false;
     r.pf=parity(u8(result));
    }else if(form===4){ // MUL
     const value=this.readRm(rm,size);
     const result=size===4?u32(this.readReg(0,4)*value):u32(this.readReg(0,1)*value);
     if(size===4){this.writeReg(0,result,4);this.writeReg(2,0,4);}else{this.writeReg(0,result,1);this.writeReg(2,0,1);}
     r.cf=false;r.of=false;r.af=false;
    }else if(form===5){ // IMUL
     const value=this.readRm(rm,size);
     const result=size===4?s32(this.readReg(0,4)*value):s32(this.readReg(0,1)*value);
     if(size===4){this.writeReg(0,result,4);this.writeReg(2,0,4);}else{this.writeReg(0,result,1);this.writeReg(2,0,1);}
     r.cf=false;r.of=false;r.af=false;
    }else if(form===6){ // DIV
     const divisor=this.readRm(rm,size);
     if(divisor===0)throw new EmulationFault('EMULATION_FAULT','Division by zero',eip);
     if(size===4){
      const dividend=BigInt(this.readReg(2,4))*0x100000000n+BigInt(this.readReg(0,4));
      const quotient=dividend/BigInt(divisor);
      if(quotient>0xffffffffn)throw new EmulationFault('EMULATION_FAULT','Division overflow',eip);
      this.writeReg(0,Number(quotient),4);this.writeReg(2,Number(dividend%BigInt(divisor)),4);
     }else{
      const dividend=this.readReg(0,2),div=this.readReg(2,2);
      if(div===0)throw new EmulationFault('EMULATION_FAULT','Division by zero',eip);
      this.writeReg(0,Math.floor(dividend/div),2);this.writeReg(2,dividend%div,2);
     }
    }else{ // IDIV
     const divisor=s32(this.readRm(rm,size));
     if(divisor===0)throw new EmulationFault('EMULATION_FAULT','Division by zero',eip);
     if(size===4){
      const dividend=BigInt(s32(this.readReg(2,4)))*0x100000000n+BigInt(u32(this.readReg(0,4)));
      const quotient=dividend/BigInt(divisor);
      if(quotient>0x7fffffffn||quotient< -0x80000000n)throw new EmulationFault('EMULATION_FAULT','Division overflow',eip);
      this.writeReg(0,Number(quotient),4);this.writeReg(2,Number(dividend%BigInt(divisor)),4);
     }else{
      const dividend=s32(this.readReg(0,2)),div=s32(this.readReg(2,2));
      if(div===0)throw new EmulationFault('EMULATION_FAULT','Division by zero',eip);
      this.writeReg(0,Math.trunc(dividend/div),2);this.writeReg(2,dividend%div,2);
     }
    }
    return next;
   }
   case 0xfe:case 0xff:{
    const size=opcode===0xff?4:1;
    const form=(this.fetch8(next)&0x38)>>3;next++;
    const modrm=this.fetch8(next);next++;
    const rm=this.decodeModrm(next===next?modrm:modrm,next);next=rm.next;
    if(form===0||form===1){
     const value=this.readRm(rm,size);
     const result=form===0?this.alu(0,value,1,false):this.alu(5,value,1,false);
     this.writeRm(rm,result,size);
     return next;
    }
    if(opcode===0xfe)throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported group 4 opcode',eip);
    if(form===2||form===4){ // CALL r/m
     const target=this.readRm(rm,4);
     this.push32(next);
     return target;
    }
    if(form===3||form===5){ // JMP r/m
     return this.readRm(rm,4);
    }
    if(form===6){ // PUSH r/m
     this.push32(this.readRm(rm,4));
     return next;
    }
    throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported group 5 opcode',eip);
   }
  }
 }
 private executeTwoByte(second:number,eip:number,next:number):number{
  const r=this.registers;
  if(second>=0x80&&second<=0x8f){ // Jcc rel32
   const displacement=s32(this.fetch32(next));next+=4;
   if(this.condition(second&0x0f))next=u32(next+displacement);
   return next;
  }
  if(second>=0x90&&second<=0x9f){ // SETcc r/m8
   const modrm=this.fetch8(next);next++;
   const rm=this.decodeModrm(modrm,next);next=rm.next;
   this.writeRm(rm,this.condition(second&0x0f)?1:0,1);
   return next;
  }
  if(second>=0x40&&second<=0x4f){ // CMOVcc r32, r/m32
   const modrm=this.fetch8(next);next++;
   const rm=this.decodeModrm(modrm,next);next=rm.next;
   if(this.condition(second&0x0f))this.writeReg(rm.reg,this.readRm(rm,4),4);
   return next;
  }
  if(second===0xaf){ // IMUL r32, r/m32
   const modrm=this.fetch8(next);next++;
   const rm=this.decodeModrm(modrm,next);next=rm.next;
   const result=s32(this.readReg(rm.reg,4)*this.readRm(rm,4));
   this.writeReg(rm.reg,result,4);
   // The architecture leaves the auxiliary carry undefined after a multiply.
   r.cf=false;r.of=false;r.af=false;r.zf=result===0;r.sf=(result&0x80000000)!==0;r.pf=parity(u8(result));
   return next;
  }
  if(second===0xb6||second===0xb7){ // MOVZX
   const size=second===0xb7?4:2;
   const modrm=this.fetch8(next);next++;
   const rm=this.decodeModrm(modrm,next);next=rm.next;
   this.writeReg(rm.reg,this.readRm(rm,size),4);
   return next;
   }
  if(second===0xbe||second===0xbf){ // MOVSX
   const size=second===0xbf?4:2;
   const modrm=this.fetch8(next);next++;
   const rm=this.decodeModrm(modrm,next);next=rm.next;
   const raw=this.readRm(rm,size);
   this.writeReg(rm.reg,size===4?s32(raw):s32(raw&0xffff),4);
   return next;
  }
  if(second===0x1f){ // NOP r/m
   const modrm=this.fetch8(next);next++;
   const rm=this.decodeModrm(modrm,next);next=rm.next;
   return next;
  }
  throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported two byte opcode 0f '+second.toString(16),eip);
 }
 private alu(form:number,left:number,right:number,carry:boolean):number{
  const r=this.registers;
  switch(form){
   case 0:return this.setFlagsAdd(left,right,carry?1:0);
   case 1:{const result=u32(left|right);this.setFlagsLogic(result);return result;}
   case 2:{const result=this.setFlagsAdd(left,right,carry?1:0);return result;}
   case 3:{const result=this.setFlagsSub(left,right,carry?1:0);return result;}
   case 4:{const result=u32(left&right);this.setFlagsLogic(result);return result;}
   case 5:{const result=this.setFlagsSub(left,right,carry?1:0);return result;}
   case 6:{const result=u32(left^right);this.setFlagsLogic(result);return result;}
   case 7:{const result=this.setFlagsSub(left,right,carry?1:0);return result;}
   default:throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported ALU form',null);
  }
 }
 private shift(form:number,value:number,count:number,size:number):number{
  const bits=size*8;
  const masked=count&(bits-1);
  const r=this.registers;
  if(masked===0){this.setFlagsShift(value,0);return value;}
  switch(form){
   case 0:{ // ROL
    const result=u32((value<<masked)|(value>>>(bits-masked)));
    r.cf=(result&1)!==0;
    return result;
   }
   case 1:{ // ROR
    const result=u32((value>>>masked)|(value<<(bits-masked)));
    r.cf=(result&(1<<(bits-1)))!==0;
    return result;
   }
   case 2:{ // RCL
    const carryIn=r.cf?1:0;
    const wide=(BigInt(u32(value))<<1n)|BigInt(carryIn);
    const result=Number((wide<<BigInt(masked))|(wide>>BigInt(bits-masked)))>>>0;
    r.cf=(result&(1<<(bits-1)))!==0;
    return result;
   }
   case 3:{ // RCR
    const carryIn=r.cf?1:0;
    const wide=BigInt(u32(value))|BigInt(carryIn<<bits);
    const result=Number((wide>>BigInt(masked))|(wide<<BigInt(bits-masked)))>>>0;
    r.cf=(result&1)!==0;
    return result;
   }
   case 4:{ // SHL
    const result=u32(value<<masked);
    this.setFlagsShift(result,masked);
    r.cf=masked>0&&((value<<(masked-1))&(1<<(bits-1)))!==0;
    return result;
   }
   case 5:{ // SHR
    const result=u32(value>>>masked);
    this.setFlagsShift(result,masked);
    r.cf=masked>0&&((value>>>(masked-1))&1)!==0;
    return result;
   }
   case 6:{ // SAR
    const result=u32(s32(value)>>masked);
    this.setFlagsShift(result,masked);
    r.cf=masked>0&&((s32(value)>>(masked-1))&1)!==0;
    return result;
   }
   default:throw new EmulationFault('EMULATION_UNSUPPORTED_OPCODE','Unsupported shift form',null);
  }
 }
 private readReg(index:number,size:number):number{
  const r=this.registers;
  const names:RegisterName[]=['eax','ecx','edx','ebx','esp','ebp','esi','edi'];
  if(index===4&&size===1)return r.esp&0xff;
  if(index===5&&size===1)return r.ebp&0xff;
  if(index===6&&size===1)return r.esi&0xff;
  if(index===7&&size===1)return r.edi&0xff;
  const name=names[index]!;
  const value=r.get(name);
  return size===1?value&0xff:value;
 }
 private readRegName(name:RegisterName,size:number):number{
  const value=this.registers.get(name);
  return size===1?value&0xff:value;
 }
 private writeRegName(name:RegisterName,value:number,size:number):void{
  const names:RegisterName[]=['eax','ecx','edx','ebx','esp','ebp','esi','edi'];
  const index=names.indexOf(name);
  this.writeReg(index<0?0:index,value,size);
 }
 private writeReg(index:number,value:number,size:number):void{
  const r=this.registers;
  const names:RegisterName[]=['eax','ecx','edx','ebx','esp','ebp','esi','edi'];
  if(index===4&&size===1){r.esp=u32((r.esp&0xffffff00)|(value&0xff));return;}
  if(index===5&&size===1){r.ebp=u32((r.ebp&0xffffff00)|(value&0xff));return;}
  if(index===6&&size===1){r.esi=u32((r.esi&0xffffff00)|(value&0xff));return;}
  if(index===7&&size===1){r.edi=u32((r.edi&0xffffff00)|(value&0xff));return;}
  r.set(names[index]!,size===1?u32(value):value);
 }
 private writeReg8(index:number,value:number):void{
  const r=this.registers;
  const names:RegisterName[]=['eax','ecx','edx','ebx','esp','ebp','esi','edi'];
  if(index<4){const current=r.get(names[index]!);r.set(names[index]!,u32((current&0xffffff00)|(value&0xff)));}
  else this.writeReg(index,value,1);
 }
 private readRm(rm:{address:number|null;reg:number;rm:number;size:number},size:number):number{
  if(rm.address!==null)return size===1?this.read8(rm.address):size===2?this.read16(rm.address):this.read32(rm.address);
  return this.readReg(rm.rm,size);
 }
 private writeRm(rm:{address:number|null;reg:number;rm:number;size:number},value:number,size:number):void{
  if(rm.address!==null){
   if(size===1)this.write8(rm.address,value);
   else if(size===2)this.write16(rm.address,value);
   else this.write32(rm.address,value);
   return;
  }
  if(size===1)this.writeReg8(rm.rm,value);
  else this.writeReg(rm.rm,value,size);
 }
 /** Decodes a ModRM byte into an operand address and a register index. */
 private decodeModrm(modrm:number,next:number):{address:number|null;reg:number;rm:number;size:number;next:number}{
  const mod=modrm>>6,reg=(modrm>>3)&0x07,rmField=modrm&0x07;
  let cursor=next;
  // In register addressing the operand register is the r/m field, not the
  // reg field. The reg field selects the other operand of the opcode.
  if(mod===3)return {address:null,reg,rm:rmField,size:0,next};
  let base:number|null=null;
  let index:number|null=null;
  let scale=1;
  let displacement=0;
  let displacementSize=0;
  if(rmField===4){ // SIB
   const sib=this.fetch8(cursor);cursor++;
   const ss=sib>>6,sIndex=(sib>>3)&0x07,sBase=sib&0x07;
   scale=1<<ss;
   index=sIndex===4?null:this.readReg(sIndex,4);
   if(sBase===5&&mod===0){displacement=s32(this.fetch32(cursor));cursor+=4;displacementSize=4;base=null;}
   else base=this.readReg(sBase,4);
  }else if(rmField===5&&mod===0){ // RIP relative, treated as absolute in this interpreter
   displacement=s32(this.fetch32(cursor));cursor+=4;displacementSize=4;
   return {address:u32(displacement),reg,rm:rmField,size:0,next:cursor};
  }else{
   base=this.readReg(rmField,4);
  }
  if(mod===1){displacement=signExtend8(this.fetch8(cursor));cursor+=1;displacementSize=1;}
  else if(mod===2){displacement=s32(this.fetch32(cursor));cursor+=4;displacementSize=4;}
  else if(mod===0&&rmField===5){displacement=0;}
  let address:number|null=null;
  if(base!==null||index!==null){
   let effective=base??0;
   if(index!==null)effective=u32(effective+index*scale);
   address=u32(effective+displacement);
  }
  void displacementSize;
  return {address,reg,rm:rmField,size:0,next:cursor};
 }
}

function parity(value:number):boolean{
 let count=0;
 for(let index=0;index<8;index++)if((value>>index)&1)count++;
 return count%2===0;
}
