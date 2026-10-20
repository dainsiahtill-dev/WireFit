/* Fixed native-kernel experiment. No input supplies code, RVA, symbol or PID. */
'use strict';
(function () {
    function requireValue(ok, message) { if (!ok) throw new Error(message); }
    function exact(value, keys) {
        requireValue(value !== null && typeof value === 'object' && !Array.isArray(value) &&
            Object.keys(value).sort().join('|') === keys.slice().sort().join('|'), 'Unexpected contract fields');
    }
    function validateCase(value) {
        exact(value, ['id','width','height','node_stride','source_stride','labels']);
        requireValue(typeof value.id === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(value.id), 'Invalid case id');
        const w=value.width,h=value.height;
        requireValue(Number.isInteger(w)&&w>=2&&w<=16&&Number.isInteger(h)&&h>=2&&h<=16, 'Invalid dimensions');
        requireValue(Number.isInteger(value.node_stride)&&value.node_stride>=w+1&&value.node_stride<=w+8, 'Invalid node stride');
        requireValue(Number.isInteger(value.source_stride)&&value.source_stride>=w&&value.source_stride<=w+8, 'Invalid source stride');
        requireValue(Array.isArray(value.labels)&&value.labels.length===w*h&&value.labels.every(v=>Number.isInteger(v)&&v>=-2147483648&&v<=2147483647), 'Invalid int32 labels');
        return value;
    }
    function validateSetup(value) {
        exact(value,['profile']);
        requireValue(['positive-control','vmde-grid'].includes(value.profile), 'Unknown fixed profile');
        return value;
    }
    function layout(value, page) {
        validateCase(value);
        requireValue(Number.isInteger(page)&&page>=4096&&page<=65536&&(page&(page-1))===0, 'Unsupported page size');
        const sizes={context:156,header:12,source:value.source_stride*value.height*4,nodes:value.node_stride*(value.height+1)*4};
        requireValue(Object.values(sizes).every(n=>n>0&&n+64<=page&&n%4===0), 'Buffer exceeds guarded data page');
        return sizes;
    }
    function allChecks(checks) { return Object.keys(checks).length>0&&Object.values(checks).every(v=>v===true); }
    const WRAPPER_HEX='5589e55356578b551089e0894204895a0c897210897a14896a18fc9c5889028b4d0cff55088b551089423089e0894208895a1c897220897a24896a289c5889422c8d65f45f5e5b5dc3';
    globalThis.WirefitNativeKernel={validateCase,validateSetup,layout,allChecks,wrapper_hex:WRAPPER_HEX};
    if (typeof rpc === 'undefined') return;
    const BODY_SHA='65d46a13deb731ea75b91fd29baf96dc614da6ad8bfcf48805aba748a139f70c';
    let configuration=null, anchor=null, wrapperBlock=null, wrapper=null, halted=false, count=0;
    function hex(buffer) { return Array.from(new Uint8Array(buffer),v=>v.toString(16).padStart(2,'0')).join(''); }
    function bytesFromHex(value) { return value.match(/../g).map(v=>parseInt(v,16)); }
    function read(address,size) { const b=address.readVolatile(size);requireValue(b!==null&&b.byteLength===size,'Incomplete memory read');return b; }
    function hash(buffer) { return Checksum.compute('sha256',buffer); }
    function current() {
        requireValue(configuration!==null,'Agent is not configured');
        const m=Process.mainModule;
        requireValue(m.base.toString()===anchor.base&&m.path===anchor.path&&m.size===anchor.size,'Main module identity changed');
        const entry=configuration.profile==='vmde-grid'?m.base.add(0x98a50):m.getExportByName('wirefit_grid_control');
        const size=configuration.profile==='vmde-grid'?637:64;
        const start=BigInt(entry.toString()),base=BigInt(m.base.toString());
        requireValue(start>=base&&start+BigInt(size)<=base+BigInt(m.size)&&start+BigInt(size)<=0x100000000n,'Entry outside main image');
        const region=Process.findRangeByAddress(entry);
        requireValue(region!==null&&region.protection.includes('r')&&region.protection.includes('x')&&entry.add(size).compare(region.base.add(region.size))<=0,'Entry not completely readable executable');
        const body=read(entry,size),digest=hash(body);
        return {pid:Process.id,arch:Process.arch,pointer_size:Process.pointerSize,main:{base:m.base.toString(),size:m.size,path:m.path},entry:entry.toString(),body_size_bytes:size,body_sha256:digest,body_hex:hex(body),ready:configuration.profile==='positive-control'||digest===BODY_SHA};
    }
    function compact(identity) { return {main_base:identity.main.base,entry:identity.entry,body_sha256:identity.body_sha256}; }
    function protection(address,size,value) {
        requireValue(Memory.protect(address,size,value),'Memory protection request failed');
        requireValue(Memory.queryProtection(address)===value&&Memory.queryProtection(address.add(size-1))===value,'Memory protection confirmation failed');
    }
    function guarded(name,size,page) {
        const backing=Memory.alloc(page*3),middle=backing.add(page),data=middle.add(page-size);
        requireValue(!backing.isNull()&&BigInt(backing.toString())%BigInt(page)===0n&&BigInt(backing.toString())+BigInt(page*3)<=0x100000000n,'Invalid page allocation');
        middle.writeByteArray(new Uint8Array(page).fill(0xa5));
        protection(middle,page,'rw-');
        protection(backing,page,'---');protection(backing.add(page*2),page,'---');
        return {name,size,backing,middle,data,end:backing.add(page*3),before:null};
    }
    function ensureDisjoint(blocks) {
        for(let i=0;i<blocks.length;i++) for(let j=i+1;j<blocks.length;j++)
            requireValue(blocks[i].end.compare(blocks[j].backing)<=0||blocks[j].end.compare(blocks[i].backing)<=0,'Synthetic allocations overlap');
    }
    function registerState(state) {
        const result={};
        const names=['eflags_before','esp_before','esp_after','ebx_before','esi_before','edi_before','ebp_before','ebx_after','esi_after','edi_after','ebp_after','eflags_after','eax_incidental'];
        names.forEach((name,i)=>result[name]=state.add(i*4).readU32());
        return result;
    }
    function registerChecks(state) {
        return {direction_flag_clear:(state.eflags_before&0x400)===0,return_direction_flag_clear:(state.eflags_after&0x400)===0,
            stack_balanced:state.esp_before===state.esp_after,
            callee_saved_unchanged:['ebx','esi','edi','ebp'].every(r=>state[r+'_before']===state[r+'_after'])};
    }
    function prepareWrapper() {
        wrapperBlock=Memory.alloc(Process.pageSize);
        wrapperBlock.writeByteArray(bytesFromHex(WRAPPER_HEX));
        protection(wrapperBlock,Process.pageSize,'r-x');
        wrapper=new NativeFunction(wrapperBlock,'void',['pointer','pointer','pointer'],{abi:'mscdecl',scheduling:'cooperative',exceptions:'steal',traps:'none'});
    }
    function run(value) {
        validateCase(value);requireValue(!halted,'Experiment halted after a failed call');
        const row={id:value.id,status:'failed',evidence:{invocation_started:false,invocation_returned:false,capture_errors:[]}};
        const start=Date.now();
        function retainError(error) {
            if(row.error===undefined)row.error={code:'NATIVE_KERNEL_CALL_FAILED',message:String(error).slice(0,2048)};
        }
        function capture(component,operation) {
            try { return operation(); }
            catch(error) {
                row.evidence.capture_errors.push({component,message:String(error).slice(0,2048)});
                retainError(error);return null;
            }
        }
        try {
            const before=current();requireValue(before.ready,'Original body identity is unavailable');
            row.evidence.before=compact(before);
            const page=Process.pageSize,sizes=layout(value,page),blocks=Object.entries(sizes).map(([name,size])=>guarded(name,size,page));
            ensureDisjoint(blocks);
            const by=Object.fromEntries(blocks.map(block=>[block.name,block]));
            const context=by.context.data,header=by.header.data,pixels=by.source.data,nodes=by.nodes.data;
            header.writePointer(pixels);header.add(4).writeU32(value.source_stride);header.add(8).writeU32(value.height);
            value.labels.forEach((label,i)=>pixels.add((Math.floor(i/value.width)*value.source_stride+i%value.width)*4).writeS32(label));
            for(const [offset,v] of [[0,nodes],[4,value.node_stride],[8,value.height+1],[12,header],[0x94,value.width],[0x98,value.height]])
                if(typeof v==='number')context.add(offset).writeU32(v);else context.add(offset).writePointer(v);
            row.evidence.buffers=blocks.map(b=>({name:b.name,allocation:b.backing.toString(),data:b.data.toString(),size_bytes:b.size,data_page:b.middle.toString(),page_size:page,protection:b.name==='nodes'?'rw-':'r--'}));
            row.evidence.buffer_before_sha256={};
            for(const block of blocks) {
                const contents=read(block.middle,page);block.before=hex(contents);
                row.evidence.buffer_before_sha256[block.name]=hash(contents);
                if(block.name!=='nodes') protection(block.middle,page,'r--');
            }
            const state=Memory.alloc(52);state.writeByteArray(new Uint8Array(52).fill(0xa5));
            const immediate=current();requireValue(immediate.ready&&immediate.body_sha256===before.body_sha256,'Body changed during buffer setup');
            row.evidence.invocation_started=true;
            try { wrapper(ptr(immediate.entry),context,state);row.evidence.invocation_returned=true; }
            catch(error) { retainError(error); }
            // Failed native calls retain independent best-effort observations.
            // A later read failure must never replace the original exception.
            row.evidence.raw_register_state_hex=capture('raw_register_state',()=>hex(read(state,52)));
            const registers=row.evidence.invocation_returned?capture('registers',()=>registerState(state)):null;
            row.evidence.registers=registers;
            row.evidence.register_observation=registers===null?'unavailable_wrapper_did_not_return_or_read_failed':'captured_by_wrapper';
            const after=capture('body_after',current);
            if(after!==null)row.evidence.after=compact(after);
            const checks=registers===null?{direction_flag_clear:false,return_direction_flag_clear:false,stack_balanced:false,callee_saved_unchanged:false}:registerChecks(registers);
            checks.body_unchanged=after!==null&&after.ready&&after.body_sha256===before.body_sha256;
            checks.wrapper_unchanged=capture('wrapper_after',()=>hex(read(wrapperBlock,WRAPPER_HEX.length/2))===WRAPPER_HEX)===true;
            row.evidence.buffer_after_sha256={};
            for(const block of blocks) {
                const observed=capture(block.name+'_data_after',()=>read(block.middle,page));
                const observedHex=observed===null?null:hex(observed);
                if(observed!==null)row.evidence.buffer_after_sha256[block.name]=hash(observed);
                checks[block.name+'_prefix_canary']=observedHex!==null&&observedHex.slice(0,(page-block.size)*2)===block.before.slice(0,(page-block.size)*2);
                if(block.name!=='nodes')checks[block.name+'_immutable']=observedHex!==null&&observedHex===block.before;
                checks[block.name+'_guards']=capture(block.name+'_guards_after',()=>Memory.queryProtection(block.backing)==='---'&&Memory.queryProtection(block.backing.add(page*2))==='---')===true;
                checks[block.name+'_protection']=capture(block.name+'_protection_after',()=>Memory.queryProtection(block.middle)===(block.name==='nodes'?'rw-':'r--'))===true;
            }
            row.evidence.checks=checks;
            const actualBytes=capture('output_after',()=>read(nodes,sizes.nodes));
            if(actualBytes!==null) {
                row.evidence.output_hex=hex(actualBytes);row.evidence.output_sha256=hash(actualBytes);
                // Decode the exact captured bytes once; a second native read could race.
                const view=new DataView(actualBytes);
                row.output=Array.from({length:sizes.nodes/4},(_,i)=>view.getInt32(i*4,true));
            }
            requireValue(allChecks(checks)&&row.evidence.capture_errors.length===0,'Native call violated a declared invariant');
            if(row.error===undefined) { row.status='completed';count++; }
        } catch(error) { retainError(error); }
        if(row.status!=='completed')halted=true;
        row.evidence.elapsed_ms=Date.now()-start;
        return row;
    }
    rpc.exports={
        setup(value) {
            requireValue(configuration===null,'Setup is one-shot');validateSetup(value);
            requireValue(Process.platform==='windows'&&Process.arch==='ia32'&&Process.pointerSize===4,'Requires Windows x86 target');
            configuration=value;
            const m=Process.mainModule;anchor={base:m.base.toString(),size:m.size,path:m.path};
            prepareWrapper();
            let probe=null;
            if(value.profile==='positive-control') {
                const p=Memory.alloc(156),nodes=Memory.alloc(64);p.writeByteArray(new Uint8Array(156).fill(0));p.writePointer(nodes);
                const fn=new NativeFunction(m.getExportByName('wirefit_abi_probe'),'uint',['pointer','uint'],{abi:'thiscall',scheduling:'cooperative',exceptions:'steal',traps:'none'});
                const tag=0x8f31d2a5,result=fn(p,tag);
                probe={context:p.toString(),observed_context:nodes.readPointer().toString(),tag,result,expected:(tag^0x5a17c3e9)>>>0};
                requireValue(probe.context===probe.observed_context&&probe.result===probe.expected,'Compiled thiscall positive control failed');
            }
            return {profile:value.profile,arch:Process.arch,pointer_size:4,main:anchor,abi_probe:probe,
                wrapper_hex:WRAPPER_HEX,wrapper_sha256:hash(read(wrapperBlock,WRAPPER_HEX.length/2)),direction_flag:'explicit CLD immediately before CALL',semantic_return:'void'};
        },
        identity:current,
        run,
        finish() { return {completed_calls:count,halted}; }
    };
})();