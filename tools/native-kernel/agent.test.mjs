import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const source = await readFile(new URL('./agent.js', import.meta.url), 'utf8').catch(() => '');
const sandbox = vm.createContext({});
vm.runInContext(source, sandbox);
const api = sandbox.WirefitNativeKernel;
const sample = () => ({id:'edge-a',width:2,height:2,node_stride:3,source_stride:2,labels:[0,-1,2147483647,-2147483648]});
test('exports bounded contract without requiring a Frida process', () => assert.equal(typeof api?.validateCase, 'function'));
test('accepts signed int32 extremes and bounded padding', () => assert.equal(api.validateCase(sample()).labels.length, 4));
for (const [name, alter] of [
 ['extra request field', c => c.pid=5], ['nonfinite dimension', c => c.width=Infinity],
 ['boolean dimension', c => c.width=true], ['too small dimension', c => c.width=1],
 ['too large dimension', c => c.height=17], ['undersized output', c => c.node_stride=2],
 ['too large output stride', c => c.node_stride=11], ['undersized source', c => c.source_stride=1],
 ['too large source stride', c => c.source_stride=11], ['missing label', c => c.labels.pop()],
 ['int32 overflow', c => c.labels[0]=2147483648], ['fractional label', c => c.labels[0]=0.5],
 ['boolean label', c => c.labels[0]=true], ['nul id', c => c.id='bad\u0000id'],
 ['oversized id', c => c.id='a'.repeat(129)],
]) test('rejects '+name, () => {const c=sample();alter(c);assert.throws(()=>api.validateCase(c));});
test('separates positive-control and fixed original profile', () => {
 assert.equal(api.validateSetup({profile:'positive-control'}).profile,'positive-control');
 assert.equal(api.validateSetup({profile:'vmde-grid'}).profile,'vmde-grid');
 for(const c of [{profile:'anything'}, {profile:'vmde-grid',rva:'0x1'}, {profile:'vmde-grid',pid:1}]) assert.throws(()=>api.validateSetup(c));
});
test('computes actual source and node buffer bytes from strides', () => {
 const c=sample(); c.node_stride=10;c.source_stride=10;
 const layout=api.layout(c,4096);
 assert.equal(layout.context,156);assert.equal(layout.header,12);assert.equal(layout.source,80);assert.equal(layout.nodes,120);
});
test('rejects invalid host page size before any memory operation', () => {
 for(const page of [0,156,4095,8193,NaN]) assert.throws(()=>api.layout(sample(),page));
});
test('an unchanged guard is mandatory in every declared check', () => {
 assert.equal(api.allChecks({input_immutable:true,output_prefix_canary:true,source_canary:true}),true);
 assert.equal(api.allChecks({input_immutable:true,output_prefix_canary:false}),false);
 assert.equal(api.allChecks({}),false);
 assert.equal(api.allChecks({input_immutable:1}),false);
});