import {createHash} from 'node:crypto';
import {assert} from '../shared.js';
import type {ResearchSplit,SplitName,SplitView} from './types.js';

/** The split seed is owned by the specification; a request may not change it. */
export const RESEARCH_SPLIT_SEED=20261019;

/** The canonical split rule, recorded verbatim in every frozen plan. */
export const RESEARCH_SPLIT_RULE=
 'bucket = sha256(seed + "\\0" + row_id) first 4 bytes big-endian mod 5; bucket 0 or 1 -> train; bucket 2 -> validation; bucket 3 or 4 -> holdout';

/**
 * Deterministic bucket of one row identifier.
 * `sha256(seed + "\0" + row_id)` truncated to four bytes, read big-endian.
 */
export function splitBucket(seed:number,rowId:string):number{
 assert(Number.isInteger(seed)&&seed>=0,'SPLIT_INVALID','Split seed must be a non-negative integer');
 assert(typeof rowId==='string'&&rowId.length>0,'SPLIT_INVALID','Split row identifier must be a nonempty string');
 const digest=createHash('sha256').update(seed+'\0'+rowId,'utf8').digest();
 return digest.readUInt32BE(0)%5;
}

/** Split assignment of one row identifier. */
export function assignSplit(seed:number,rowId:string):SplitName{
 const bucket=splitBucket(seed,rowId);
 if(bucket===0||bucket===1)return 'train';
 if(bucket===2)return 'validation';
 return 'holdout';
}

/**
 * Holds the full assignment and hands out only the develop-visible view.
 *
 * The holdout identifiers exist inside the guard because the evaluate phase
 * needs them, but `developView()` returns an object that has no `holdout`
 * property at all: a direction implementation cannot reach holdout rows
 * through the develop context even by mistake.
 */
export class SplitGuard{
 private readonly assignment:Map<string,SplitName>;
 private readonly train:string[]=[];
 private readonly validation:string[]=[];
 private readonly holdout:string[]=[];
 constructor(readonly seed:number,readonly rowIds:readonly string[]){
  this.assignment=new Map<string,SplitName>();
  for(const rowId of rowIds){
   assert(!this.assignment.has(rowId),'SPLIT_INVALID','Duplicate row identifier: '+rowId);
   const name=assignSplit(seed,rowId);
   this.assignment.set(rowId,name);
   if(name==='train')this.train.push(rowId);
   else if(name==='validation')this.validation.push(rowId);
   else this.holdout.push(rowId);
  }
 }
 counts():{train:number;validation:number;holdout:number}{
  return {train:this.train.length,validation:this.validation.length,holdout:this.holdout.length};
 }
 /** Train and validation identifiers only. There is no holdout accessor here. */
 developView():SplitView{
  return {train:Object.freeze([...this.train]),validation:Object.freeze([...this.validation])};
 }
 /** Holdout identifiers, reachable only from the evaluate phase. */
 holdoutRows():readonly string[]{return Object.freeze([...this.holdout]);}
 isHoldout(rowId:string):boolean{return this.assignment.get(rowId)==='holdout';}
 splitOf(rowId:string):SplitName{
  const name=this.assignment.get(rowId);
  assert(name!==undefined,'SPLIT_INVALID','Unknown row identifier: '+rowId);
  return name;
 }
 /** Stable identity of the holdout row identifier set, in ascending order. */
 holdoutRowIdsSha256():string{
  const sorted=[...this.holdout].sort();
  return createHash('sha256').update(sorted.join('\n'),'utf8').digest('hex');
 }
 /**
  * Compares the observed counts with the pre-registered expectation.
  * A mismatch is a specification defect, never a scientific outcome.
  */
 verifyExpectedCounts(expected:ResearchSplit['expected_counts']):void{
  const observed=this.counts();
  assert(
   observed.train===expected.train&&observed.validation===expected.validation&&observed.holdout===expected.holdout,
   'SPLIT_COUNT_MISMATCH',
   'Split counts do not match the pre-registered expectation: observed '+
    JSON.stringify(observed)+' expected '+JSON.stringify(expected),
  );
 }
}

/**
 * Scans the develop phase artifacts for holdout row identifiers.
 *
 * This is the second gate of the split discipline. The first gate is
 * structural: the develop context has no holdout accessor at all. That gate
 * is not an operating system isolation and an implementation that opens a
 * corpus file directly could still see holdout content. This scan is what
 * detects such a leak after the fact.
 *
 * Identifiers are matched on token boundaries. A plain substring search would
 * report a false leak whenever one identifier is a prefix of another, for
 * example `four-cell-1` inside `four-cell-100`.
 */
export function detectHoldoutLeak(
 artifacts:readonly {value:unknown}[],
 holdout:readonly string[],
):string[]{
 const needles=holdout.filter((needle)=>needle.length>=4);
 const found=new Set<string>();
 const isTokenCharacter=(character:string|undefined):boolean=>
  character!==undefined&&/[A-Za-z0-9_-]/.test(character);
 const containsToken=(haystack:string,needle:string):boolean=>{
  let from=0;
  for(;;){
   const index=haystack.indexOf(needle,from);
   if(index<0)return false;
   const before=index===0?undefined:haystack[index-1];
   const after=haystack[index+needle.length];
   if(!isTokenCharacter(before)&&!isTokenCharacter(after))return true;
   from=index+1;
  }
 };
 const visit=(value:unknown,depth:number):void=>{
  if(depth>12||value===null||value===undefined)return;
  if(typeof value==='string'){
   for(const needle of needles)if(containsToken(value,needle))found.add(needle);
   return;
  }
  if(typeof value!=='object')return;
  if(Array.isArray(value)){for(const item of value)visit(item,depth+1);return;}
  for(const [key,item] of Object.entries(value as Record<string,unknown>)){
   if(needles.includes(key))found.add(key);
   visit(item,depth+1);
  }
 };
 for(const artifact of artifacts)visit(artifact.value,0);
 return [...found].sort();
}
