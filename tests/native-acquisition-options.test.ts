import {describe,expect,it} from 'vitest';
import path from 'node:path';
import {parseAcquisitionArgs} from '../src/native-acquisition-options.js';

const required=['--file','sample.exe','--config','tool.json','--plan','plan.json','--out','new-capture','--python',process.execPath,'--capture-at-ms','24000'];
describe('owned acquisition arguments',()=>{
 it('requires explicit interpreter and timing while preserving independent worker configuration',()=>{
  const result=parseAcquisitionArgs([...required,'--caller-rva','0x1A','--caller-rva','0x0020','--powershell',process.execPath]);
  expect(result).toEqual({file:path.resolve('sample.exe'),config:path.resolve('tool.json'),plan:path.resolve('plan.json'),out:path.resolve('new-capture'),python:process.execPath,powershell:process.execPath,capture_at_ms:24000,callers:['0x1a','0x20']});
 });
 it('makes private and window capture explicitly not requested when omitted',()=>{
  const result=parseAcquisitionArgs(required);expect(result.callers).toEqual([]);expect(result.powershell).toBeUndefined();
 });
 it.each([
  ['--pid','2'],['--case','existing'],['--agent','injected.js'],['--python',process.execPath],['--capture-at-ms','1'],['--caller-rva','0x100000000'],['--caller-rva','12'],['--caller-rva','0x0','--caller-rva','0x000'],['--powershell','pwsh'],['--unknown','x'],['--caller-rva'],
 ])('rejects unsupported, duplicate or malformed argument tail %j',(...tail)=>{
  expect(()=>parseAcquisitionArgs([...required,...tail])).toThrow();
 });
 it.each(['-1','NaN','1.2','60000','Infinity','+1',' 1'])('rejects ambiguous or out-of-window capture offset %s',value=>{
  const args=[...required];args[args.indexOf('--capture-at-ms')+1]=value;
  expect(()=>parseAcquisitionArgs(args)).toThrow();
 });
 it('rejects missing required options and more than sixteen callers',()=>{
  expect(()=>parseAcquisitionArgs(required.slice(0,-2))).toThrow();
  expect(()=>parseAcquisitionArgs([...required,...Array.from({length:17},(_,i)=>['--caller-rva','0x'+i.toString(16)]).flat()])).toThrow();
 });
});
