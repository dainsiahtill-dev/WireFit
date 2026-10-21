import {assert} from '../shared.js';
import {selectPath} from './recipe.js';
import type {EvidenceResolver} from './evidence.js';
import type {EvidencePin,EvidencePinSpec} from './types.js';

/**
 * A corpus unit: the evidence role that carries the rows of one split unit
 * and the field that identifies a row.
 *
 * The split is owned by the specification, but the rows it partitions come
 * from the corpus. The runner resolves the unit named by `split.unit` and
 * verifies that the direction actually declared the backing evidence role.
 */
export interface CorpusUnit{
 role:string;
 kind:'json'|'jsonl';
 /** Path into a JSON document; omitted for JSON Lines corpora. */
 path?:string;
 /** Property carrying the row identifier; when absent the array index is used. */
 id_field?:string;
}

export const CORPUS_UNITS:Record<string,CorpusUnit>={
 grid:{role:'grid_observations',kind:'jsonl',id_field:'id'},
 accepted_functions:{role:'fresh_business_code',kind:'json',path:'candidates[*].entry_va',id_field:'entry_va'},
 segmentation_scenarios:{role:'segmentation_result',kind:'json',path:'scenarios[*].id',id_field:'id'},
 kernel_layout_offsets:{role:'grid_kernel_facts',kind:'json',path:'kernel_layout[*].offset',id_field:'offset'},
 module_image_intervals:{role:'module_image_json',kind:'json',path:'coverage.pages[*].rva',id_field:'rva'},
 private_closure_instructions:{role:'private_closure_callpop',kind:'json',path:'listing[*].pc',id_field:'pc'},
 module_slot_events:{role:'module_slots_receipt',kind:'json',path:'trace_raw.events[*]'},
};

/**
 * Loads pinned evidence and registers it under a stable role name.
 *
 * Roles are the indirection that lets one audit recipe serve seventeen
 * heterogeneous directions: a check names an artifact role, never a file path,
 * so the same kernel can be replayed from a frozen artifact or from the
 * original evidence file.
 */
export class CorpusLoader{
 private readonly documents=new Map<string,unknown>();
 private readonly rows=new Map<string,unknown[]>();
 private readonly binaries=new Map<string,Buffer>();
 private readonly pins=new Map<string,EvidencePin>();
 private readonly specs=new Map<string,EvidencePinSpec>();
 constructor(private readonly resolver:EvidenceResolver){}
 /** Registers a pin under its role without reading it yet. */
 declare(pin:EvidencePinSpec):void{
  assert(!this.specs.has(pin.role),'CORPUS_ROLE_DUPLICATE','Duplicate evidence role: '+pin.role);
  this.specs.set(pin.role,pin);
 }
 /** Reads one declared pin and registers its content under its role. */
 async load(role:string):Promise<EvidencePin>{
  const spec=this.specs.get(role);
  assert(spec!==undefined,'CORPUS_ROLE_UNKNOWN','Unknown evidence role: '+role);
  const cached=this.pins.get(role);
  if(cached!==undefined)return cached;
  const {bytes,observed}=await this.resolver.resolve(spec);
  this.binaries.set(role,bytes);
  this.pins.set(role,observed);
  return observed;
 }
 /** Reads and parses one declared JSON document. */
 async json<T=unknown>(role:string):Promise<T>{
  const spec=this.specs.get(role);
  assert(spec!==undefined,'CORPUS_ROLE_UNKNOWN','Unknown evidence role: '+role);
  if(this.documents.has(role))return this.documents.get(role) as T;
  if(spec.path.endsWith('.jsonl')){
   await this.jsonl(role);
   return this.documents.get(role) as T;
  }
  const {value,observed}=await this.resolver.resolveJson(spec);
  this.pins.set(role,observed);
  this.documents.set(role,value);
  return value as T;
 }
 /**
  * Loads every declared evidence pin so that the recipe can read it.
  *
  * The recipe kernel interface is synchronous, so an evidence role must be
  * materialised before a check runs. JSON and JSON Lines pins become
  * documents, every other pin becomes a binary.
  */
 async primeAll():Promise<EvidencePin[]>{
  for(const [role,spec] of this.specs){
   if(this.pins.has(role))continue;
   if(spec.path.endsWith('.jsonl'))await this.jsonl(role);
   else if(spec.path.endsWith('.json')){
    await this.json(role);
    const bytes=await this.binary(role);
    this.binaries.set(role,bytes);
   }
   else await this.binary(role);
  }
  return this.observedPins();
 }
 /** Reads and parses one declared JSON Lines document. */
 async jsonl<T=unknown>(role:string):Promise<T[]>{
  const spec=this.specs.get(role);
  assert(spec!==undefined,'CORPUS_ROLE_UNKNOWN','Unknown evidence role: '+role);
  if(this.rows.has(role))return this.rows.get(role) as T[];
  const {rows,observed}=await this.resolver.resolveJsonl(spec);
  this.pins.set(role,observed);
  this.rows.set(role,rows);
  // The recipe addresses a JSON Lines corpus as {"rows": [...]}. The loader
  // API returns the raw rows, but the registered document always carries the
  // wrapped shape so that the path language sees one representation.
  this.documents.set(role,{rows});
  return rows as T[];
 }
 /** Reads one declared binary artifact. */
 async binary(role:string):Promise<Buffer>{
  const spec=this.specs.get(role);
  assert(spec!==undefined,'CORPUS_ROLE_UNKNOWN','Unknown evidence role: '+role);
  const cached=this.binaries.get(role);
  if(cached!==undefined)return cached;
  const {bytes,observed}=await this.resolver.resolve(spec);
  this.binaries.set(role,bytes);
  this.pins.set(role,observed);
  return bytes;
 }
 /** Registers an in-memory document produced by the experiment itself. */
 registerDocument(role:string,value:unknown):void{
  assert(!this.documents.has(role),'CORPUS_ROLE_DUPLICATE','Duplicate corpus role: '+role);
  this.documents.set(role,value);
 }
 /** Registers an in-memory binary produced by the experiment itself. */
 registerBinary(role:string,bytes:Buffer):void{
  assert(!this.binaries.has(role),'CORPUS_ROLE_DUPLICATE','Duplicate corpus role: '+role);
  this.binaries.set(role,bytes);
 }
 /** Returns a registered document. */
 document(role:string):unknown{
  assert(this.documents.has(role),'CORPUS_ROLE_UNKNOWN','Unknown corpus role: '+role);
  return this.documents.get(role);
 }
 /** Returns a registered binary. */
 bytes(role:string):Buffer{
  assert(this.binaries.has(role),'CORPUS_ROLE_UNKNOWN','Unknown corpus role: '+role);
  return this.binaries.get(role)!;
 }
 /** Observed pins, in declaration order. */
 observedPins():EvidencePin[]{
  const output:EvidencePin[]=[];
  for(const [role,spec] of this.specs){
   const observed=this.pins.get(role);
   output.push(observed??{...spec,observed_sha256_before:null,observed_sha256_after:null,verified:false});
  }
  return output;
 }
 /** The registered in-memory documents, keyed by role. */
 registeredDocuments():Map<string,unknown>{return new Map(this.documents);}
}
