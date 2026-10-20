import {it,expect} from 'vitest';
import {deriveStatus,checkNumericComparisonDomain} from '../src/verification.js';
import {readJson,rootDir} from '../src/shared.js';
import path from 'node:path';
it('never reports matched for zero or incomplete observations',()=>{
 expect(deriveStatus({planned:0,attempted:0,completed:0,matched:0,mismatched:0,failed:0,out_of_domain:0})).toBe('unavailable');
 expect(deriveStatus({planned:2,attempted:2,completed:1,matched:1,mismatched:0,failed:1,out_of_domain:0})).toBe('partial');
 expect(deriveStatus({planned:2,attempted:2,completed:2,matched:1,mismatched:1,failed:0,out_of_domain:0})).toBe('mismatch');
});
it('checks representable FP32 domain nonemptiness and actual containment',async()=>{
 const model=await readJson<any>(path.join(rootDir,'examples/model.affine-initial.json'));
 const mapping={inputs:[{left:'x',right:'x'}],outputs:[{left:'result',right:'result'}]};
 expect(()=>checkNumericComparisonDomain(model,model,{constraints:[]},mapping)).toThrow(/domain/i);
 const empty={constraints:[{input:'x',op:'eq',value:{kind:'fp32',bits:'0x00000000'}},{input:'x',op:'ne',value:{kind:'fp32',bits:'0x80000000'}}]};
 expect(()=>checkNumericComparisonDomain(model,model,empty,mapping)).toThrow(/empty/i);
 expect(()=>checkNumericComparisonDomain(model,model,model.domain,mapping)).not.toThrow();
});
