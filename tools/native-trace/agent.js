"use strict";

// Independent Frida 17 agent: hardware execution traps and entry-only API hooks.
// General-purpose registers, TLS callbacks, and page protections are preserved.
let config = null;
let main = null;
let finished = false;
let eventCount = 0;
let omittedEvents = 0;
let threadObserver = null;
let moduleObserver = null;
let statsTimer = null;
let reportedOmittedEvents = 0;
let hookStates = [];
let hookStateVersion = 0;
let reportedHookStateVersion = 0;
const threads = new Map();
const hooks = new Map();
const snapshotPhases = new Set();
const capturingThreads = new Set();

function message(error) { return String(error).replace(/\0/g, "?").slice(0, 2048); }
function eventCapacity() { return config.max_events - (config.max_events >= 2 ? 1 : 0); }
function emit(event, finalEvent = false) {
    const limit = finalEvent ? config.max_events : eventCapacity();
    if (eventCount >= limit) { omittedEvents++; return; }
    eventCount++;
    send({kind: "event", event});
}
function moduleInventory(phase) {
    const modules = Process.enumerateModules();
    emit({type: "module_inventory", phase, modules: modules.slice(0, 128).map(module => ({
        name: module.name.slice(0, 32), name_truncated: module.name.length > 32,
        base: module.base.toString(), size: module.size
    })), total_count: modules.length, omitted_modules: Math.max(0, modules.length - 128)}, phase === "final");
}
function fatal(error) { send({kind: "fatal", message: message(error)}); }
function copyHookStates() { return hookStates.map(state => ({...state})); }
function publishHookStates(phase) { send({kind: "hook_states", phase, states: copyHookStates()}); }
function hookError(index, error) {
    hookStates[index].status = "error";
    hookStates[index].error = message(error);
    hookStateVersion++;
    publishHookStates("current");
    fatal("Requested API hook failed: " + hookStates[index].module + "!" + hookStates[index].symbol + ": " + message(error));
}
function hex(bytes) {
    return Array.from(new Uint8Array(bytes), value => value.toString(16).padStart(2, "0")).join("");
}
function addressInfo(address) {
    const module = Process.findModuleByAddress(address);
    const range = Process.findRangeByAddress(address);
    return {address: address.toString(), module: module === null ? null : module.name,
        rva: module === null ? null : address.sub(module.base).toString(),
        protection: range === null ? null : range.protection};
}
function bytesAt(address, size) {
    try {
        const range = Process.findRangeByAddress(address);
        if (range === null || !range.protection.includes("r")) throw new Error("Memory is not readable");
        const end = range.base.add(range.size);
        const length = address.add(size).compare(end) <= 0 ? size : end.sub(address).toUInt32();
        if (length <= 0) throw new Error("No readable bytes at address");
        const data = address.readVolatile(length);
        if (data === null) throw new Error("Memory read returned null");
        return {address: address.toString(), requested_size_bytes: size, size_bytes: data.byteLength,
            hex: hex(data), error: data.byteLength === size ? null : "Read stopped at readable memory boundary"};
    } catch (error) {
        return {address: address.toString(), requested_size_bytes: size, size_bytes: 0, hex: "", error: message(error)};
    }
}
function registers(context) {
    const names = Process.arch === "ia32" ?
        ["pc", "sp", "eip", "esp", "ebp", "eax", "ebx", "ecx", "edx", "esi", "edi", "eflags"] :
        ["pc", "sp", "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"];
    const result = {};
    for (const name of names) if (context[name] !== undefined) result[name] = context[name].toString();
    return result;
}
function capture(context, returnAddress) {
    const stack = bytesAt(context.sp, 256);
    let caller = returnAddress;
    if (caller === undefined && stack.size_bytes >= Process.pointerSize) {
        const littleEndian = stack.hex.slice(0, Process.pointerSize * 2).match(/../g);
        caller = ptr("0x" + littleEndian.reverse().join(""));
    }
    let callerCode = null;
    if (caller !== undefined) {
        const range = Process.findRangeByAddress(caller);
        if (range !== null && range.protection.includes("x")) {
            const offset = caller.sub(range.base).toUInt32();
            callerCode = bytesAt(caller.sub(Math.min(32, offset)), 96);
        }
    }
    return {context: registers(context), stack, pc: addressInfo(context.pc),
        pc_code: bytesAt(context.pc, 96), return_address: caller === undefined ? null : addressInfo(caller),
        return_address_code: callerCode};
}
function snapshots(phase) {
    if (snapshotPhases.has(phase)) return;
    snapshotPhases.add(phase);
    config.ranges.forEach((range, index) => {
        const metadata = {kind: "snapshot", phase, range_index: index, rva: range.rva, size_bytes: range.size_bytes};
        if (range.module !== undefined) Object.assign(metadata, {
            module: range.module, module_base: null, module_size: null, address: null
        });
        try {
            let address;
            if (range.module === undefined) {
                address = main.base.add(range.rva);
            } else {
                // Resolve immediately before each read. Inventories are bounded
                // reporting events and never authorize or locate a snapshot.
                const matches = Process.enumerateModules().filter(module => module.name.toLowerCase() === range.module.toLowerCase());
                if (matches.length !== 1) throw new Error(matches.length === 0 ? "Requested module is not loaded" : "Requested module basename is ambiguous");
                const module = matches[0];
                const base = BigInt(module.base.toString());
                const limit = 1n << BigInt(Process.pointerSize * 8);
                if (base <= 0n || base >= limit || !Number.isInteger(module.size) || module.size < 1 || module.size > 0xffffffff ||
                    base + BigInt(module.size) > limit) throw new Error("Module interval is invalid or exceeds the target pointer width");
                metadata.module_base = module.base.toString();
                metadata.module_size = module.size;
                const offset = BigInt(range.rva), size = BigInt(range.size_bytes);
                if (offset + size > BigInt(module.size) || base + offset + size > limit) throw new Error("Requested range exceeds the loaded module");
                address = ptr("0x" + (base + offset).toString(16));
                metadata.address = address.toString();
            }
            const bytes = address.readVolatile(range.size_bytes);
            if (bytes === null || bytes.byteLength !== range.size_bytes) throw new Error("Incomplete memory snapshot");
            send(metadata, bytes);
        } catch (error) { send({...metadata, error: message(error)}); }
    });
}
function armThread(thread) {
    if (finished || threads.has(thread.id)) return;
    const record = {thread, slots: new Set()};
    threads.set(thread.id, record);
    try {
        config.breakpoints_rva.forEach((rva, slot) => {
            thread.setHardwareBreakpoint(slot, main.base.add(rva));
            record.slots.add(slot);
        });
    } catch (error) { fatal("Cannot arm target thread " + thread.id + ": " + message(error)); }
}
function onException(details) {
    const threadId = Process.getCurrentThreadId();
    const record = threads.get(threadId);
    if (!finished && record !== undefined && (details.type === "single-step" || details.type === "breakpoint")) {
        for (const slot of record.slots) {
            const rva = config.breakpoints_rva[slot];
            if (!details.context.pc.equals(main.base.add(rva))) continue;
            try {
                // Remove this thread's trap before resuming the same instruction.
                record.thread.unsetHardwareBreakpoint(slot);
                record.slots.delete(slot);
            } catch (error) {
                fatal("Cannot disarm owned breakpoint: " + message(error));
                return false;
            }
            capturingThreads.add(threadId);
            try {
                if (eventCount < eventCapacity()) {
                    emit({type: "breakpoint", thread_id: threadId, breakpoint_rva: rva,
                        ...capture(details.context)});
                } else { omittedEvents++; }
                snapshots("breakpoint-" + rva.slice(2));
            } catch (error) { fatal(error); }
            finally { capturingThreads.delete(threadId); }
            return true;
        }
    }
    // The application and Windows retain ownership of all other exceptions.
    if (!finished && !capturingThreads.has(threadId)) {
        emit({type: "native_exception", thread_id: threadId, exception_type: details.type,
            address: details.address.toString(), context: registers(details.context),
            memory: details.memory == null ? null : {
                operation: details.memory.operation, address: details.memory.address.toString()}});
    }
    return false;
}
function installHooks() {
    if (finished) return;
    config.api_hooks.forEach((request, index) => {
        if (hooks.has(index) || hookStates[index].status === "error") return;
        const module = Process.findModuleByName(request.module);
        if (module === null) return;
        try {
            const target = module.findExportByName(request.symbol);
            if (target === null) throw new Error("Loaded module does not export the requested symbol");
            const exported = module.enumerateExports().find(entry => entry.name === request.symbol);
            const range = Process.findRangeByAddress(target);
            if (exported === undefined || exported.type !== "function" || range === null || !range.protection.includes("x")) {
                throw new Error("Requested export is not an executable function");
            }
            const listener = Interceptor.attach(target, {
                onEnter() {
                    if (finished || capturingThreads.has(this.threadId)) return;
                    hookStates[index].observations++;
                    hookStateVersion++;
                    if (eventCount >= eventCapacity()) { omittedEvents++; return; }
                    capturingThreads.add(this.threadId);
                    try {
                        emit({type: "api_enter", module: request.module, symbol: request.symbol,
                            thread_id: this.threadId, ...capture(this.context, this.returnAddress)});
                    } catch (error) { fatal(error); }
                    finally { capturingThreads.delete(this.threadId); }
                }
            });
            hooks.set(index, listener);
            hookStates[index].status = "installed";
            hookStates[index].address = target.toString();
            hookStates[index].error = null;
            hookStateVersion++;
            publishHookStates("current");
        } catch (error) { hookError(index, error); }
    });
}
function checkConfig(value) {
    if (Process.platform !== "windows" || !["ia32", "x64"].includes(Process.arch)) throw new Error("Only Windows x86/x64 targets are supported");
    if (typeof Process.attachThreadObserver !== "function") throw new Error("Thread observer API is unavailable");
    for (const rva of value.breakpoints_rva) {
        if (Number.parseInt(rva, 16) >= main.size) throw new Error("Breakpoint RVA exceeds target image");
    }
    for (const range of value.ranges) {
        if (range.module === undefined && Number.parseInt(range.rva, 16) + range.size_bytes > main.size) throw new Error("Requested range exceeds target image");
    }
}
rpc.exports = {
    setup(value) {
        if (config !== null) throw new Error("Agent can only be configured once");
        config = value;
        hookStates = config.api_hooks.map(request => ({...request, status: "pending_module", observations: 0, address: null, error: null}));
        main = Process.mainModule;
        checkConfig(config);
        moduleInventory("initial");
        snapshots("initial");
        statsTimer = setInterval(() => {
            if (omittedEvents !== reportedOmittedEvents || hookStateVersion !== reportedHookStateVersion) {
                reportedOmittedEvents = omittedEvents;
                reportedHookStateVersion = hookStateVersion;
                send({kind: "stats", omitted_events: omittedEvents, hook_states: copyHookStates()});
            }
        }, 250);
        Process.setExceptionHandler(onException);
        // The observer covers thread creation races; enumeration is an explicit
        // cross-check and armThread deduplicates the observer's initial callbacks.
        threadObserver = Process.attachThreadObserver({
            onAdded(thread) { armThread(thread); },
            onRemoved(thread) { threads.delete(thread.id); }
        });
        for (const thread of Process.enumerateThreads()) armThread(thread);
        if (config.api_hooks.length > 0) {
            moduleObserver = Process.attachModuleObserver({
                onAdded() { installHooks(); },
                onRemoved(module) {
                    config.api_hooks.forEach((request, index) => {
                        if (request.module.toLowerCase() !== module.name.toLowerCase() || !hooks.has(index)) return;
                        hooks.get(index).detach();
                        hooks.delete(index);
                        hookStates[index].status = "pending_module";
                        hookStates[index].address = null;
                        hookStateVersion++;
                    });
                    publishHookStates("current");
                }
            });
            installHooks();
        }
        publishHookStates("initial");
        return {frida_version: Frida.version, arch: Process.arch, pointer_size: Process.pointerSize,
            image_base: main.base.toString(), image_size: main.size, initial_threads: threads.size,
            hardware_breakpoints: config.breakpoints_rva.length, installed_api_hooks: hooks.size};
    },
    finish() {
        if (config === null) throw new Error("Agent has not been configured");
        if (!finished) {
            snapshots("final");
            moduleInventory("final");
            finished = true;
            if (statsTimer !== null) clearInterval(statsTimer);
            if (threadObserver !== null) threadObserver.detach();
            if (moduleObserver !== null) moduleObserver.detach();
            for (const record of threads.values()) {
                for (const slot of record.slots) {
                    try { record.thread.unsetHardwareBreakpoint(slot); }
                    catch (error) { emit({type: "breakpoint_cleanup_error", thread_id: record.thread.id, message: message(error)}); }
                }
                record.slots.clear();
            }
            for (const listener of hooks.values()) listener.detach();
            for (const state of hookStates) if (state.status === "pending_module") state.status = "unobserved";
            publishHookStates("final");
        }
        return {omitted_events: omittedEvents, snapshot_phases: Array.from(snapshotPhases), hook_states: copyHookStates()};
    }
};
