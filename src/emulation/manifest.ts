import {createHash} from 'node:crypto';
import {assert} from '../shared.js';
import {Memory,X86Interpreter,type AccessRange,type EmulationFault,type RegisterName} from './x86.js';

/**
 * The declarative native function emulation request.
 *
 * The request is data, not code: it names the function bytes, the memory the
 * function may see, how the caller's arguments are placed into memory, and
 * how the results are read back. Nothing in it can execute anything.
 */
export interface EmulationCode{
 file:string;
 sha256:string;
 file_offset:number;
 virtual_address:number;
 size_bytes:number;
}

export interface EmulationRegionSpec{
 name:string;
 base:number;
 size_bytes:number;
 read:boolean;
 write:boolean;
 execute:boolean;
}

export type EmulationEncoding='bytes_hex'|'int32_le'|'uint32_le'|'int8';

export interface EmulationMemoryFill{
 region:string;
 offset:number;
 encoding:EmulationEncoding;
 value?:number;
 value_expression?:string;
 fill_hex?:string;
 repeat?:number;
 count_expression?:string;
}

export interface EmulationInputFill{
 input:string;
 region:string;
 offset:number;
 encoding:EmulationEncoding;
 element_size?:number;
 stride_bytes?:number;
 stride_expression?:string;
 elements_per_row_expression?:string;
 count_expression?:string;
}

export interface EmulationOutputSpec{
 id:string;
 source:{kind:'register'|'memory';register?:string;region?:string;offset?:number;size_bytes?:number};
 encoding:'bv32'|'bv64'|'uint32'|'int32'|'fp32';
}

export interface EmulationCaptureSpec{
 id:string;
 region:string;
 offset:number;
 size_expression?:string;
}

export interface EmulationRequest{
 schema_version:1;
 emulation_id:string;
 title?:string;
 code:EmulationCode;
 regions:EmulationRegionSpec[];
 initial_memory?:EmulationMemoryFill[];
 input_fills?:EmulationInputFill[];
 registers?:Partial<Record<RegisterName,number>>;
 call:{stack_region:string;stack_pointer_offset:number;return_address:number;stop_address:number};
 outputs:EmulationOutputSpec[];
 captures?:EmulationCaptureSpec[];
 policy?:{readable?:{region:string;offset?:number;size_bytes?:number}[];writable?:{region:string;offset?:number;size_bytes?:number}[]};
 budget:{max_instructions:number};
 notes?:string;
}

/** The values a corpus row contributes to the emulated memory. */
export type EmulationRow=Record<string,unknown>;

/** The result of one emulated call. */
export interface EmulationOutcome{
 outputs:Record<string,{encoding:string;value:string;number:number}>;
 captures:Record<string,{sha256:string;size_bytes:number;bytes_hex:string}>;
 instructions_executed:number;
 visited_instructions:number;
 final_eip:number;
 final_esp:number;
 fault:{code:string;message:string}|null;
}

/**
 * A small arithmetic expression over the numeric fields of a corpus row.
 *
 * The grammar is `+ - * / %`, parentheses and identifiers. It exists so that a
 * manifest can say "four labels per row" without embedding code, and it is
 * evaluated here rather than with `eval`.
 */
export function evaluateExpression(expression:string,row:EmulationRow):number{
 const text=expression.trim();
 let position=0;
 const peek=():string=>text[position]??'';
 const eat=(token:string):void=>{
  assert(text.startsWith(token,position),'EMULATION_EXPRESSION_INVALID','Expected "'+token+'" in '+expression);
  position+=token.length;
 };
 const parseNumber=():number=>{
  const match=/^[0-9]+/.exec(text.slice(position));
  assert(match!==null,'EMULATION_EXPRESSION_INVALID','Expected a number in '+expression);
  position+=match[0].length;
  return Number(match[0]);
 };
 const parseIdentifier=():number=>{
  const match=/^[A-Za-z_][A-Za-z0-9_]*/.exec(text.slice(position));
  assert(match!==null,'EMULATION_EXPRESSION_INVALID','Expected an identifier in '+expression);
  position+=match[0].length;
  const value=row[match[0]];
  assert(typeof value==='number'&&Number.isFinite(value),'EMULATION_EXPRESSION_INVALID',
   'The expression field "'+match[0]+'" is not a finite number in the corpus row.');
  return value;
 };
 const parseFactor=():number=>{
  if(peek()==='-'){eat('-');return -parseFactor();}
  if(peek()==='('){eat('(');const value=parseSum();assert(peek()===')','EMULATION_EXPRESSION_INVALID','Unbalanced parenthesis in '+expression);eat(')');return value;}
  if(/[0-9]/.test(peek()))return parseNumber();
  return parseIdentifier();
 };
 const parseTerm=():number=>{
  let value=parseFactor();
  for(;;){
   if(peek()==='*'){eat('*');value=value*parseFactor();continue;}
   if(peek()==='/'){eat('/');const divisor=parseFactor();assert(divisor!==0,'EMULATION_EXPRESSION_INVALID','Division by zero in '+expression);value=Math.trunc(value/divisor);continue;}
   if(peek()==='%'){eat('%');const divisor=parseFactor();assert(divisor!==0,'EMULATION_EXPRESSION_INVALID','Division by zero in '+expression);value=value%divisor;continue;}
   return value;
  }
 };
 const parseSum=():number=>{
  let value=parseTerm();
  for(;;){
   if(peek()==='+'){eat('+');value+=parseTerm();continue;}
   if(peek()==='-'){eat('-');value-=parseTerm();continue;}
   return value;
  }
 };
 const result=parseSum();
 assert(position===text.length,'EMULATION_EXPRESSION_INVALID','Trailing characters in '+expression);
 assert(Number.isSafeInteger(result),'EMULATION_EXPRESSION_INVALID','The expression did not evaluate to an integer.');
 return result;
}

function bytesFor(fill:{encoding:EmulationEncoding;value?:number;value_expression?:string;fill_hex?:string;repeat?:number;count_expression?:string},row:EmulationRow):Buffer{
 if(fill.encoding==='bytes_hex'){
  const pattern=Buffer.from(fill.fill_hex??'', 'hex');
  assert(pattern.length>0,'EMULATION_FILL_INVALID','A bytes_hex fill needs a nonempty fill_hex.');
  const count=fill.count_expression!==undefined?evaluateExpression(fill.count_expression,row):(fill.repeat??1);
  assert(count>0&&count<=1048576,'EMULATION_FILL_INVALID','The fill repeat count is out of range.');
  return Buffer.concat(Array.from({length:count},()=>pattern));
 }
 const value=fill.value_expression!==undefined?evaluateExpression(fill.value_expression,row):(fill.value??0);
 if(fill.encoding==='int8')return Buffer.from([value&0xff]);
 const out=Buffer.alloc(4);
 out.writeInt32LE(value|0,0);
 return out;
}

/** Encodes one corpus value with the requested encoding. */
export function encodeValue(value:unknown,encoding:EmulationEncoding):Buffer{
 if(encoding==='bytes_hex'){
  assert(typeof value==='string','EMULATION_INPUT_INVALID','A bytes_hex input must be a hexadecimal string.');
  return Buffer.from(value,'hex');
 }
 assert(typeof value==='number'&&Number.isFinite(value),'EMULATION_INPUT_INVALID','A numeric input is required.');
  const out=Buffer.alloc(4);
 if(encoding==='int32_le')out.writeInt32LE(value|0,0);
 else if(encoding==='uint32_le')out.writeUInt32LE(value>>>0,0);
 else out.writeInt8(value|0,0);
 return out;
}

/** Formats one output value in the requested encoding. */
export function formatOutput(raw:Buffer,encoding:string):{encoding:string;value:string;number:number}{
 if(encoding==='fp32'){
  const value=raw.readFloatLE(0);
  return {encoding,value:'0x'+raw.readUInt32LE(0).toString(16).padStart(8,'0'),number:value};
 }
 if(encoding==='bv64'){
  const value=raw.readBigUInt64LE(0);
  return {encoding,value:'0x'+value.toString(16).padStart(16,'0'),number:Number(value)};
 }
 if(encoding==='int32'){
  const value=raw.readInt32LE(0);
  return {encoding,value:'0x'+raw.readUInt32LE(0).toString(16).padStart(8,'0'),number:value};
 }
 if(encoding==='uint32'){
  const value=raw.readUInt32LE(0);
  return {encoding,value:'0x'+value.toString(16).padStart(8,'0'),number:value};
 }
 const value=raw.readUInt32LE(0);
 return {encoding:'bv32',value:'0x'+value.toString(16).padStart(8,'0'),number:value};
}

/** Reads the code bytes of a request from its file and checks the digest. */
export function readCodeBytes(request:EmulationRequest,readFile:(file:string)=>Promise<Buffer>):Promise<Buffer>{
 return (async()=>{
  const bytes=await readFile(request.code.file);
  assert(createHash('sha256').update(bytes).digest('hex')===request.code.sha256,'EMULATION_CODE_IDENTITY',
   'The emulated file does not match the digest declared by the manifest.');
  assert(bytes.length>=request.code.file_offset+request.code.size_bytes,'EMULATION_CODE_TRUNCATED',
   'The file does not contain the declared code range.');
  return bytes.subarray(request.code.file_offset,request.code.file_offset+request.code.size_bytes);
 })();
}

/** The access ranges a policy declares, resolved against the regions. */
export function policyRanges(
 request:EmulationRequest,
 entries:{region:string;offset?:number;size_bytes?:number}[]|undefined,
):AccessRange[]{
 const output:AccessRange[]=[];
 for(const entry of entries??[]){
  const region=request.regions.find((candidate)=>candidate.name===entry.region);
  assert(region!==undefined,'EMULATION_POLICY_INVALID','The policy names an undeclared region: '+entry.region);
  const offset=entry.offset??0;
  const size=entry.size_bytes??(region!.size_bytes-offset);
  output.push({base:region!.base+offset,size_bytes:size});
 }
 return output;
}

/** Runs one emulated call and returns its outputs and captures. */
export async function executeEmulation(
 request:EmulationRequest,
 code:Buffer,
 row:EmulationRow,
):Promise<EmulationOutcome>{
 const memory=new Memory(request.regions.map((region)=>({...region})));
 memory.loadBytes(request.code.virtual_address,code);
 const regionBase=(name:string):number=>{
  const region=request.regions.find((candidate)=>candidate.name===name);
  assert(region!==undefined,'EMULATION_REGION_UNKNOWN','The manifest names an undeclared region: '+name);
  return region!.base;
 };
 for(const fill of request.initial_memory??[])
  memory.loadBytes(regionBase(fill.region)+fill.offset,bytesFor(fill,row));
 for(const fill of request.input_fills??[]){
  const value=row[fill.input];
  assert(value!==undefined,'EMULATION_INPUT_MISSING','The corpus row has no field "'+fill.input+'".');
  if(Array.isArray(value)){
   const count=fill.count_expression!==undefined?evaluateExpression(fill.count_expression,row):value.length;
   const elementSize=fill.element_size??4;
   const stride=fill.stride_expression!==undefined?evaluateExpression(fill.stride_expression,row):(fill.stride_bytes??elementSize);
   assert(Number.isSafeInteger(stride)&&stride>=elementSize,'EMULATION_FILL_INVALID','The element stride must be an integer of at least the element size.');
   /*
    * A row major array is placed with the declared stride: element i belongs
    * to row floor(i / elementsPerRow) and column i % elementsPerRow, so the
    * destination offset is row * stride + column * elementSize. Without the
    * row length the flat index would be multiplied by the stride and every
    * row after the first would be misplaced.
    */
   const elementsPerRow=fill.elements_per_row_expression!==undefined
    ?evaluateExpression(fill.elements_per_row_expression,row):count;
   assert(elementsPerRow>0,'EMULATION_FILL_INVALID','The row length must be positive.');
   assert(stride>=elementsPerRow*elementSize,'EMULATION_FILL_INVALID','The element stride must hold a whole row.');
   const rows=Math.ceil(count/elementsPerRow);
   const out=Buffer.alloc((rows-1)*stride+elementsPerRow*elementSize);
   for(let index=0;index<count;index++){
    const row=Math.floor(index/elementsPerRow),column=index%elementsPerRow;
    encodeValue(value[index],fill.encoding).copy(out,row*stride+column*elementSize);
   }
   memory.loadBytes(regionBase(fill.region)+fill.offset,out);
   continue;
  }
  memory.loadBytes(regionBase(fill.region)+fill.offset,encodeValue(value,fill.encoding));
 }
 const stackBase=regionBase(request.call.stack_region);
 memory.loadBytes(stackBase+request.call.stack_pointer_offset,
  Buffer.from([request.call.return_address&0xff,(request.call.return_address>>>8)&0xff,
   (request.call.return_address>>>16)&0xff,(request.call.return_address>>>24)&0xff]));
 const cpu=new X86Interpreter({
  memory,
  budget:{max_instructions:request.budget.max_instructions,max_memory_bytes:1<<26},
  readable:policyRanges(request,request.policy?.readable),
  writable:policyRanges(request,request.policy?.writable),
 });
 for(const [name,value] of Object.entries(request.registers??{}))cpu.registers.set(name as RegisterName,value);
 cpu.registers.eip=request.code.virtual_address;
 cpu.registers.esp=stackBase+request.call.stack_pointer_offset;
 const result=cpu.run(request.call.stop_address);
 const outputs:EmulationOutcome['outputs']={};
 for(const output of request.outputs){
  let raw:Buffer;
  if(output.source.kind==='register'){
   assert(typeof output.source.register==='string','EMULATION_OUTPUT_INVALID','A register output needs a register.');
   raw=Buffer.alloc(8);
   raw.writeUInt32LE(cpu.registers.get(output.source.register as RegisterName)>>>0,0);
   raw.writeUInt32LE(Math.floor(cpu.registers.get(output.source.register as RegisterName)/0x100000000)>>>0,4);
  }else{
   assert(typeof output.source.region==='string'&&typeof output.source.offset==='number',
    'EMULATION_OUTPUT_INVALID','A memory output needs a region and an offset.');
   raw=Buffer.from(memory.readBytes(regionBase(output.source.region)+output.source.offset,output.source.size_bytes??4));
  }
  outputs[output.id]=formatOutput(raw,output.encoding);
 }
 const captures:EmulationOutcome['captures']={};
 for(const capture of request.captures??[]){
  const size=capture.size_expression!==undefined?evaluateExpression(capture.size_expression,row):0;
  const bytes=Buffer.from(memory.readBytes(regionBase(capture.region)+capture.offset,size));
  captures[capture.id]={sha256:createHashOf(bytes),size_bytes:bytes.length,bytes_hex:bytes.toString('hex')};
 }
 return {
  outputs,
  captures,
  instructions_executed:result.instructions_executed,
  visited_instructions:result.visited_instructions,
  final_eip:result.final_eip,
  final_esp:result.final_esp,
  fault:result.fault===null?null:{code:result.fault.code,message:result.fault.message},
 };
}

function createHashOf(bytes:Buffer):string{
 return createHash('sha256').update(bytes).digest('hex');
}

export type {EmulationFault};
