import {describe,it,expect} from 'vitest';
import {readFile,readdir} from 'node:fs/promises';
import path from 'node:path';

const DIRECTIONS=path.join('src','research','directions');

describe('research direction isolation',()=>{
 it('lets no direction implementation import another direction implementation',async()=>{
  const files=(await readdir(DIRECTIONS)).filter((name)=>name.endsWith('.ts'));
  expect(files.length).toBeGreaterThan(1);
  for(const name of files){
   if(name==='index.ts')continue;
   const source=await readFile(path.join(DIRECTIONS,name),'utf8');
   const imports=[...source.matchAll(/from\s+'([^']+)'/g)].map((match)=>match[1]!);
   for(const target of imports){
    if(!target.startsWith('./'))continue;
    const referenced=target.replace(/^\.\//,'').replace(/\.js$/,'')+'.ts';
    expect(
     !files.includes(referenced)||referenced===name,
     name+' imports another direction implementation: '+target,
    ).toBe(true);
   }
  }
 });
 it('keeps every direction implementation inside the directions folder',async()=>{
  const source=await readFile(path.join(DIRECTIONS,'index.ts'),'utf8');
  expect(source).toContain('directionImplementation');
  expect(source).toContain('registeredDirectionIds');
 });
});
