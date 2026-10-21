import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {
 compareCodePoints,
 compareObservation,
 encodeScalar,
 evaluateKernel,
 normalizeScalar,
 parsePath,
 selectPath,
} from '../src/research/recipe.js';

function code(action:()=>unknown):string{
 try{action();return '';}
 catch(error){return (error as {code?:string}).code??(error as Error).message;}
}

const document={
 groups:[
  {cases:[{matched:true,count:3},{matched:false,count:4}]},
  {cases:[{matched:true,count:5}]},
 ],
 scalars:[3,4,5,3],
 flat:{value:7},
 table:[
  {key:'0000',indicator:0},
  {key:'0101',indicator:1},
 ],
 text:'hello world',
 binary:'AQID',
 empty:[],
};

function context(){
 const binaries:Record<string,Buffer>={blob:Buffer.from([1,2,3,1,2,3,9])};
 const documents:Record<string,unknown>={doc:document};
 return {
  document:(role:string):unknown=>{if(role!=='doc')throw new Error('unknown role');return documents[role];},
  bytes:(role:string):Buffer=>{if(role!=='blob')throw new Error('unknown role');return binaries[role];},
 };
}

describe('research recipe kernels',()=>{
 it('parses the restricted path language and rejects malformed segments',()=>{
  expect(parsePath('groups[*].cases[*].matched')).toEqual([
   {name:'groups',index:'*'},{name:'cases',index:'*'},{name:'matched',index:null},
  ]);
  expect(parsePath('groups[0].cases[2]')).toEqual([{name:'groups',index:0},{name:'cases',index:2}]);
  expect(()=>parsePath('groups[?].cases')).toThrow();
  expect(()=>parsePath('9bad')).toThrow();
  expect(()=>parsePath('')).toThrow();
 });
 it('selects nodes with wildcards, indices and plain properties',()=>{
  expect(selectPath(document,'groups[*].cases[*].matched')).toEqual([true,false,true]);
  expect(selectPath(document,'groups[0].cases[1].count')).toEqual([4]);
  expect(selectPath(document,'groups')).toHaveLength(1);
  expect(code(()=>selectPath(document,'groups[9]'))).toBe('RECIPE_PATH_INVALID');
  expect(code(()=>selectPath(document,'missing'))).toBe('RECIPE_PATH_INVALID');
 });
 it('computes row_count, distinct_count and field_count',()=>{
  const ctx=context();
  expect(evaluateKernel(ctx,{kernel:'row_count',artifact_role:'doc',path:'groups[*].cases[*].matched'})).toBe(3);
  expect(evaluateKernel(ctx,{kernel:'distinct_count',artifact_role:'doc',path:'scalars[*]'})).toBe(3);
  expect(evaluateKernel(ctx,{kernel:'field_count',artifact_role:'doc',path:'groups[*].cases[*].matched',value:true})).toBe(2);
  expect(evaluateKernel(ctx,{kernel:'field_count',artifact_role:'doc',path:'groups[*].cases[*].matched',value:false})).toBe(1);
 });
 it('computes field_sum, field_min and field_max over integers only',()=>{
  const ctx=context();
  expect(evaluateKernel(ctx,{kernel:'field_sum',artifact_role:'doc',path:'scalars[*]'})).toBe(15);
  expect(evaluateKernel(ctx,{kernel:'field_min',artifact_role:'doc',path:'scalars[*]'})).toBe(3);
  expect(evaluateKernel(ctx,{kernel:'field_max',artifact_role:'doc',path:'scalars[*]'})).toBe(5);
  expect(code(()=>evaluateKernel(ctx,{kernel:'field_sum',artifact_role:'doc',path:'text'}))).toBe('RECIPE_VALUE_TYPE_MISMATCH');
  expect(code(()=>evaluateKernel(ctx,{kernel:'field_sum',artifact_role:'doc',path:'groups[*].cases[0]'}))).toBe('RECIPE_VALUE_TYPE_MISMATCH');
 });
 it('treats an empty selection as false for all_equal and zero for the counting kernels',()=>{
  const ctx=context();
  const empty={kernel:'all_equal',artifact_role:'doc',path:'empty[*]',value:1};
  expect(evaluateKernel(ctx,empty)).toBe(false);
  expect(evaluateKernel(ctx,{kernel:'distinct_count',artifact_role:'doc',path:'empty[*]'})).toBe(0);
  expect(evaluateKernel(ctx,{kernel:'field_count',artifact_role:'doc',path:'empty[*]',value:1})).toBe(0);
  expect(evaluateKernel(ctx,{kernel:'any_equal',artifact_role:'doc',path:'empty[*]',value:1})).toBe(false);
  expect(code(()=>evaluateKernel(ctx,{kernel:'field_sum',artifact_role:'doc',path:'empty[*]'}))).toBe('RECIPE_EMPTY_SELECTION');
 });
 it('serializes sets with a type prefix and compares them as sets',()=>{
  const ctx=context();
  const serialized=evaluateKernel(ctx,{kernel:'set_equality',artifact_role:'doc',path:'table[*].indicator'});
  expect(serialized).toBe('n:0|n:1');
  expect(evaluateKernel(ctx,{kernel:'set_equality',artifact_role:'doc',path:'table[*].key'})).toBe('s:0000|s:0101');
  expect(encodeScalar(1)).toBe('n:1');
  expect(encodeScalar('1')).toBe('s:1');
  expect(encodeScalar(true)).toBe('b:true');
  expect(encodeScalar(null)).toBe('z:null');
 });
 it('compares two paths for set equality when a second role is present',()=>{
  const ctx=context();
  expect(evaluateKernel(ctx,{kernel:'set_equality',artifact_role:'doc',path:'table[*].indicator',second_artifact_role:'doc',second_path:'scalars[*]'})).toBe(false);
 });
 it('hashes a pinned file and counts overlapping byte patterns',()=>{
  const ctx=context();
  const digest=createHash('sha256').update(Buffer.from([1,2,3,1,2,3,9])).digest('hex');
  expect(evaluateKernel(ctx,{kernel:'file_sha256',artifact_role:'blob'})).toBe(digest);
  expect(evaluateKernel(ctx,{kernel:'byte_pattern_count',artifact_role:'blob',pattern_hex:'010203'})).toBe(2);
  expect(evaluateKernel(ctx,{kernel:'byte_pattern_count',artifact_role:'blob',pattern_hex:'010203010203'})).toBe(1);
 });
 it('applies the nine comparators with the documented semantics',()=>{
  expect(compareObservation(3,3,'eq')).toBe(true);
  expect(compareObservation(3,'3','eq')).toBe(false);
  expect(compareObservation(3,4,'ne')).toBe(true);
  expect(compareObservation(3,3,'gte')).toBe(true);
  expect(compareObservation(3,3,'lte')).toBe(true);
  expect(compareObservation(3,4,'gt')).toBe(false);
  expect(compareObservation(3,4,'lt')).toBe(true);
  expect(compareObservation('n:1|n:2','n:2|n:1','identical_set')).toBe(true);
  expect(compareObservation('n:1','n:1|n:2','subset')).toBe(true);
  expect(compareObservation('n:1|n:2','n:1','superset')).toBe(true);
  expect(compareObservation(3,'x','gte')).toBe(false);
 });
 it('normalizes integral floats and orders by code point',()=>{
  expect(normalizeScalar(1.0)).toBe(1);
  expect(normalizeScalar(1.5)).toBe(1.5);
  expect(compareCodePoints('a','b')).toBeLessThan(0);
  expect(compareCodePoints('b','a')).toBeGreaterThan(0);
  expect(compareCodePoints('a','a')).toBe(0);
 });
 it('does not provide a float mean kernel',()=>{
  const kernels=JSON.parse(JSON.stringify({kernels:['row_count','distinct_count','field_count','field_sum','field_min','field_max','all_equal','any_equal','set_equality','file_sha256','byte_pattern_count']}));
  expect(kernels.kernels).not.toContain('field_mean');
 });
});
