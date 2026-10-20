// Synthetic Frida memory/runtime only. No process is spawned and no PE is loaded.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import vm from 'node:vm';

const agentSource=await readFile(new URL('./agent.js',import.meta.url),'utf8');
const BODY_SHA='65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c';
const PAGE=4096;
const sample=()=>({id:'runtime-path',width:2,height:2,node_stride:3,source_stride:2,labels:[0,-1,2147483647,-2147483648]});

/** Byte-level mock, with real page permission checks and no native execution. */
export function createHarness(mode='normal',source=agentSource) {
    const allocations=[],permissions=new Map(),protectionCalls=[];
    let next=0x10000000,nativeCalls=0;
    function blockAt(address,size) {
        const hits=allocations.filter(row=>row.base<=address&&address+size<=row.base+row.bytes.length);
        assert.equal(hits.length,1,'mock address must resolve to one retained allocation');
        return hits[0];
    }
    function permitted(address,size,access) {
        for(let page=Math.floor(address/PAGE)*PAGE;page<address+size;page+=PAGE)
            if(!permissions.get(page)?.includes(access))throw Error('synthetic protection fault: '+access);
    }
    class Pointer {
        constructor(address) { this.address=Number(address); }
        add(offset) { return new Pointer(this.address+Number(offset)); }
        compare(other) { return Math.sign(this.address-other.address); }
        toString() { return '0x'+this.address.toString(16); }
        isNull() { return this.address===0; }
        readVolatile(size) {
            permitted(this.address,size,'r');const row=blockAt(this.address,size);
            return Uint8Array.from(row.bytes.subarray(this.address-row.base,this.address-row.base+size)).buffer;
        }
        writeByteArray(value) {
            const bytes=ArrayBuffer.isView(value)?new Uint8Array(value.buffer,value.byteOffset,value.byteLength):
                Object.prototype.toString.call(value)==='[object ArrayBuffer]'?new Uint8Array(value):Uint8Array.from(value);
            permitted(this.address,bytes.length,'w');const row=blockAt(this.address,bytes.length);
            row.bytes.set(bytes,this.address-row.base);
        }
        readU32() { return new DataView(this.readVolatile(4)).getUint32(0,true); }
        readS32() { return new DataView(this.readVolatile(4)).getInt32(0,true); }
        readPointer() { return new Pointer(this.readU32()); }
        writeU32(value) { const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,value,true);this.writeByteArray(b); }
        writeS32(value) { const b=new Uint8Array(4);new DataView(b.buffer).setInt32(0,value,true);this.writeByteArray(b); }
        writePointer(value) { this.writeU32(value.address); }
    }
    function map(base,size,protection) {
        const row={base,bytes:new Uint8Array(size)};allocations.push(row);
        for(let page=base;page<base+size;page+=PAGE)permissions.set(page,protection);
        return new Pointer(base);
    }
    // Synthetic bytes/hash stand in for a body already independently pinned by
    // production. These tests exercise retention/control flow, not body identity.
    map(0x498000,PAGE,'r-x');
    const main={base:new Pointer(0x400000),size:14561280,path:'C:\\synthetic-owned\\fixture.exe'};
    const Memory={
        alloc(size) {
            const base=next;next+=Math.ceil(size/PAGE)*PAGE;
            return map(base,Math.ceil(size/PAGE)*PAGE,'rw-');
        },
        protect(address,size,value) {
            assert.equal(address.address%PAGE,0);assert.equal(size%PAGE,0);
            blockAt(address.address,size);
            for(let page=address.address;page<address.address+size;page+=PAGE)permissions.set(page,value);
            protectionCalls.push({address:address.toString(),size,value});return true;
        },
        queryProtection(address) { return permissions.get(Math.floor(address.address/PAGE)*PAGE); },
    };
    const Process={id:1234,platform:'windows',arch:'ia32',pointerSize:4,pageSize:PAGE,mainModule:main,
        findRangeByAddress(address) {
            if((mode==='post-identity-throw'||mode==='partial-write-and-post-identity-throw')&&nativeCalls>0)throw Error('synthetic post identity failure');
            assert.equal(address.address,0x498a50);
            return {base:new Pointer(0x498000),size:PAGE,protection:'r-x'};
        },
    };
    function NativeFunction(address,result,args,options) {
        assert.equal(result,'void');assert.deepEqual(Array.from(args),['pointer','pointer','pointer']);
        assert.equal(options.abi,'mscdecl');assert.equal(options.scheduling,'cooperative');
        assert.equal(options.exceptions,'steal');assert.equal(options.traps,'none');
        assert.equal(Memory.queryProtection(address),'r-x');
        return (entry,context,state)=>{
            nativeCalls++;assert.equal(entry.address,0x498a50);
            const nodes=context.readPointer(),stride=context.add(4).readU32(),height=context.add(8).readU32();
            // The wrapper writes pre-call state before invoking the native body.
            for(const [offset,value] of [[0,0x202],[4,0x2000],[12,0x11111111],[16,0x22222222],[20,0x33333333],[24,0x44444444]])
                state.add(offset).writeU32(value);
            nodes.writeU32(0x12345678);
            if(mode==='partial-write-throw'||mode==='partial-write-and-post-identity-throw')throw Error('synthetic native write fault');
            for(let i=1;i<stride*height;i++)nodes.add(i*4).writeU32(0);
            for(const [offset,value] of [[8,0x2000],[28,0x11111111],[32,0x22222222],[36,0x33333333],[40,0x44444444],[44,0x202],[48,0x99999999]])
                state.add(offset).writeU32(value);
        };
    }
    const rpc={exports:null};
    const context=vm.createContext({rpc,Memory,Process,NativeFunction,ptr:value=>new Pointer(Number(BigInt(value))),
        Checksum:{compute(algorithm,bytes) {
            assert.equal(algorithm,'sha256');
            if(bytes.byteLength===637)return BODY_SHA;
            return createHash('sha256').update(new Uint8Array(bytes)).digest('hex');
        }},
    });
    vm.runInContext(source,context,{filename:'synthetic-native-kernel-agent.js'});
    rpc.exports.setup({profile:'vmde-grid'});
    return {api:rpc.exports,Memory,Pointer,protectionCalls,get nativeCalls(){return nativeCalls;}};
}

test('native partial write and exception retain actual output and halt future calls',()=>{
    const fixture=createHarness('partial-write-throw'),row=fixture.api.run(sample());
    assert.equal(row.status,'failed');assert.match(row.error.message,/synthetic native write fault/);
    assert.equal(row.evidence.invocation_started,true);
    assert.equal(row.evidence.invocation_returned,false);
    assert.equal(row.evidence.registers,null);
    assert.equal(row.evidence.register_observation,'unavailable_wrapper_did_not_return_or_read_failed');
    assert.equal(row.evidence.raw_register_state_hex.length,104);
    assert.equal(row.evidence.buffers.length,4);
    assert.deepEqual(Object.keys(row.evidence.buffer_before_sha256).sort(),['context','header','nodes','source']);
    assert.equal(row.evidence.output_hex,'78563412'+'a5'.repeat(32));
    assert.equal(row.output[0],0x12345678);assert.equal(row.output.length,9);
    assert.equal(row.evidence.output_sha256,createHash('sha256').update(Buffer.from(row.evidence.output_hex,'hex')).digest('hex'));
    assert.equal(fixture.api.finish().halted,true);assert.equal(fixture.api.finish().completed_calls,0);
    assert.throws(()=>fixture.api.run({...sample(),id:'must-not-run'}),/halted/);
    assert.equal(fixture.nativeCalls,1);
});

test('post-call identity exception retains returned register and output observations',()=>{
    const fixture=createHarness('post-identity-throw'),row=fixture.api.run(sample());
    assert.equal(row.status,'failed');assert.match(row.error.message,/synthetic post identity failure/);
    assert.equal(row.evidence.invocation_started,true);
    assert.equal(row.evidence.invocation_returned,true);
    assert.equal(row.evidence.registers.esp_before,0x2000);assert.equal(row.evidence.registers.esp_after,0x2000);
    assert.equal(row.evidence.output_hex,'78563412'+'00'.repeat(32));
    assert.equal(row.evidence.checks.body_unchanged,false);
    assert.ok(row.evidence.capture_errors.some(error=>error.component==='body_after'));
    assert.equal(fixture.api.finish().halted,true);assert.equal(fixture.api.finish().completed_calls,0);
});

test('late identity failure cannot replace the primary native exception',()=>{
    const fixture=createHarness('partial-write-and-post-identity-throw'),row=fixture.api.run(sample());
    assert.equal(row.status,'failed');assert.match(row.error.message,/synthetic native write fault/);
    assert.equal(row.evidence.invocation_returned,false);assert.equal(row.evidence.registers,null);
    assert.equal(row.evidence.output_hex,'78563412'+'a5'.repeat(32));
    assert.ok(row.evidence.capture_errors.some(error=>error.component==='body_after'&&/post identity/.test(error.message)));
    assert.equal(fixture.api.finish().halted,true);
});

test('normal path confirms read-only inputs, writable output, guards and fixed wrapper',()=>{
    const fixture=createHarness(),row=fixture.api.run(sample());
    assert.equal(row.status,'completed');assert.equal(row.error,undefined);
    assert.equal(row.evidence.invocation_started,true);assert.equal(row.evidence.capture_errors.length,0);
    assert.equal(row.evidence.invocation_returned,true);
    assert.ok(Object.values(row.evidence.checks).every(value=>value===true));
    assert.equal(row.evidence.output_hex,'78563412'+'00'.repeat(32));
    for(const block of row.evidence.buffers) {
        const base=new fixture.Pointer(Number(BigInt(block.allocation))),middle=new fixture.Pointer(Number(BigInt(block.data_page)));
        assert.equal(fixture.Memory.queryProtection(base),'---');
        assert.equal(fixture.Memory.queryProtection(base.add(PAGE*2)),'---');
        assert.equal(fixture.Memory.queryProtection(middle),block.name==='nodes'?'rw-':'r--');
        if(block.name!=='nodes')assert.throws(()=>new fixture.Pointer(Number(BigInt(block.data))).writeU32(0),/protection/);
    }
    assert.equal(fixture.api.finish().completed_calls,1);assert.equal(fixture.api.finish().halted,false);
    assert.equal(fixture.nativeCalls,1);
});
