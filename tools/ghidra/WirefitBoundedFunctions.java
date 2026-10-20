// Bounded native observations using Ghidra public APIs. No auto-analysis or target execution.
// @category Wirefit
import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TimeoutTaskMonitor;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class WirefitBoundedFunctions extends HeadlessScript {
    private final Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private long deadline;
    private Path output;
    private final Set<Address> entries = new HashSet<>();
    private int decompileSeconds;

    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
    private void checkBudget() throws Exception {
        monitor.checkCancelled();
        require(System.nanoTime() < deadline, "Bounded script wall budget exhausted");
    }
    private void keys(JsonObject object, String... expected) {
        require(object.keySet().equals(new HashSet<>(Arrays.asList(expected))), "Unexpected or missing JSON fields");
    }
    private int integer(JsonElement value, int low, int high) {
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber(), "Expected integer");
        String text = value.getAsString();
        require(text.matches("[0-9]{1,8}"), "Expected bounded decimal integer");
        int result = Integer.parseInt(text);
        require(result >= low && result <= high, "Integer outside budget");
        return result;
    }
    private String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private void write(String name, String text) throws Exception {
        require(name.matches("[A-Za-z0-9_.-]{1,120}"), "Invalid output basename");
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= 4 * 1024 * 1024, "Per-artifact output budget exceeded");
        Files.write(output.resolve(name), bytes, StandardOpenOption.CREATE_NEW);
    }
    private void json(String name, JsonElement object) throws Exception { write(name, gson.toJson(object) + "\n"); }
    private String address(Address value) { return value == null ? null : "0x" + value.toString(); }
    private JsonArray ranges(AddressSetView set) {
        JsonArray result = new JsonArray();
        AddressRangeIterator iterator = set.getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next(); JsonObject item = new JsonObject();
            item.addProperty("start", address(range.getMinAddress())); item.addProperty("end_inclusive", address(range.getMaxAddress()));
            result.add(item);
        }
        return result;
    }
    private JsonElement varnode(Varnode value) {
        if (value == null) return JsonNull.INSTANCE;
        JsonObject item = new JsonObject(); item.addProperty("space", value.getAddress().getAddressSpace().getName());
        item.addProperty("offset", "0x" + Long.toUnsignedString(value.getOffset(), 16)); item.addProperty("size_bytes", value.getSize());
        return item;
    }
    private JsonObject pcode(PcodeOp value, String pc, int ordinal) {
        JsonObject item = new JsonObject(); item.addProperty("pc", pc); item.addProperty("ordinal", ordinal);
        item.addProperty("op", value.getMnemonic()); item.add("output", varnode(value.getOutput()));
        JsonArray inputs = new JsonArray(); for (Varnode input : value.getInputs()) inputs.add(varnode(input));
        item.add("inputs", inputs); return item;
    }
    private JsonObject transfer(Address source, Address target, String kind, AddressSetView allowed) {
        JsonObject item = new JsonObject(); item.addProperty("from", address(source)); item.addProperty("to", address(target));
        item.addProperty("kind", kind); item.addProperty("outside_guard", target == null || !allowed.contains(target));
        if (target != null) {
            var block = currentProgram.getMemory().getBlock(target);
            item.addProperty("target_memory_block", block == null ? null : block.getName());
            var function = currentProgram.getFunctionManager().getFunctionAt(target);
            item.addProperty("known_symbol", function == null ? null : function.getName());
        }
        return item;
    }

    private JsonObject analyze(Address entry, int maxBytes) throws Exception {
        checkBudget(); long started = System.nanoTime(); String label = entry.toString();
        Address end = entry.addNoWrap(maxBytes - 1L);
        AddressSet allowed = new AddressSet(entry, end);
        require(currentProgram.getMemory().contains(allowed), "Selected byte guard is not fully mapped");
        var memoryBlock = currentProgram.getMemory().getBlock(entry);
        require(memoryBlock != null && memoryBlock.isExecute(), "Selected entry is not executable memory");
        JsonObject result = new JsonObject(); result.addProperty("entry_va", address(entry));
        byte[] guardedBytes = new byte[maxBytes]; currentProgram.getMemory().getBytes(entry, guardedBytes);
        result.addProperty("guarded_bytes_sha256", digest(guardedBytes));
        result.addProperty("entry_source", "explicit candidate address, not discovered identity");
        result.add("allowed_ranges", ranges(allowed)); result.addProperty("max_bytes", maxBytes);
        result.addProperty("follow_flow", "explicit finite instruction worklist; call targets and other candidate entries excluded");
        result.addProperty("incremental_code_analysis", false); result.addProperty("coverage", "partial bounded static observation of an analysis dump");
        JsonArray listing = new JsonArray(), rawPcode = new JsonArray(), edges = new JsonArray(), calls = new JsonArray(), unknown = new JsonArray();
        AddressSet body = new AddressSet(); ArrayDeque<Address> work = new ArrayDeque<>(); Set<Address> seen = new HashSet<>();
        work.add(entry); int pcodeCount = 0;
        while (!work.isEmpty()) {
            checkBudget(); Address next = work.removeFirst();
            if (!seen.add(next)) continue;
            require(seen.size() <= 2048, "Instruction worklist budget exceeded");
            if (!allowed.contains(next) || (!next.equals(entry) && entries.contains(next))) {
                unknown.add(transfer(entry, next, "guard_or_other_candidate_boundary", allowed)); continue;
            }
            Instruction instruction = currentProgram.getListing().getInstructionAt(next);
            if (instruction == null) {
                // false confines disassembly flow to the single explicit seed set; allowed is also finite.
                DisassembleCommand command = new DisassembleCommand(new AddressSet(next, next), allowed, false);
                command.enableCodeAnalysis(false);
                long millis = Math.max(1, Math.min(1000, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())));
                TimeoutTaskMonitor local = TimeoutTaskMonitor.timeoutIn(millis, TimeUnit.MILLISECONDS);
                try { command.applyTo(currentProgram, local); }
                finally { local.finished(); }
                instruction = currentProgram.getListing().getInstructionAt(next);
            }
            if (instruction == null || instruction.getMaxAddress().compareTo(end) > 0) {
                unknown.add(transfer(next, null, "undecodable_or_guard_crossing_instruction", allowed)); continue;
            }
            body.add(instruction.getMinAddress(), instruction.getMaxAddress());
            JsonObject row = new JsonObject(); row.addProperty("va", address(next)); row.addProperty("bytes", HexFormat.of().formatHex(instruction.getBytes()));
            row.addProperty("text", instruction.toString()); row.addProperty("flow_type", instruction.getFlowType().toString());
            row.addProperty("fallthrough", address(instruction.getFallThrough())); listing.add(row);
            int ordinal = 0;
            for (PcodeOp operation : instruction.getPcode()) {
                require(++pcodeCount <= 16384, "Raw p-code output budget exceeded");
                rawPcode.add(pcode(operation, address(next), ordinal++));
            }
            Address[] destinations = instruction.getFlows(); boolean call = instruction.getFlowType().isCall();
            if (call && destinations.length == 0) calls.add(transfer(next, null, "indirect_call_unresolved", allowed));
            if (instruction.getFlowType().isComputed() && !call) unknown.add(transfer(next, null, "computed_flow_unresolved", allowed));
            for (Address destination : destinations) {
                JsonObject edge = transfer(next, destination, call ? "direct_call" : "direct_flow", allowed); edges.add(edge);
                if (call) calls.add(edge);
                else if (!allowed.contains(destination) || entries.contains(destination) && !destination.equals(entry)) unknown.add(edge);
                else work.add(destination);
            }
            Address fallthrough = instruction.getFallThrough();
            if (fallthrough != null) {
                JsonObject edge = transfer(next, fallthrough, "fallthrough", allowed); edges.add(edge);
                if (!allowed.contains(fallthrough) || entries.contains(fallthrough) && !fallthrough.equals(entry)) unknown.add(edge);
                else work.add(fallthrough);
            }
        }
        result.add("body_ranges", ranges(body)); result.addProperty("body_bytes", body.getNumAddresses());
        result.addProperty("instruction_count", listing.size()); result.addProperty("raw_pcode_count", rawPcode.size());
        result.add("listing", listing); result.add("instruction_edges", edges); result.add("calls", calls); result.add("unknown_or_guard_exits", unknown);
        result.addProperty("guard", "Only listed reachable instruction bytes are in scope. Stack, memory, ABI, external calls, indirect targets and complete function boundaries are unverified.");
        json(label + ".pcode.json", rawPcode);
        require(!body.isEmpty() && body.contains(entry), "No bounded body at selected entry");
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        require(function == null, "Existing function conflicts with explicit bounded candidate body");
        function = currentProgram.getFunctionManager().createFunction("wirefit_candidate_" + label, entry, body, SourceType.USER_DEFINED);
        DecompInterface decompiler = new DecompInterface();
        JsonObject decompilation = new JsonObject(); result.add("decompilation", decompilation);
        try {
            checkBudget();
            DecompileOptions options = new DecompileOptions(); options.setMaxInstructions(2048); options.setMaxPayloadMBytes(4);
            decompiler.setOptions(options);
            require(decompiler.openProgram(currentProgram), "Decompiler refused program");
            int seconds = Math.min(decompileSeconds, (int)Math.max(1, TimeUnit.NANOSECONDS.toSeconds(deadline - System.nanoTime())));
            decompilation.addProperty("timeout_seconds", seconds);
            DecompileResults decoded = decompiler.decompileFunction(function, seconds, monitor);
            decompilation.addProperty("completed", decoded.decompileCompleted()); decompilation.addProperty("timed_out", decoded.isTimedOut());
            decompilation.addProperty("cancelled", decoded.isCancelled()); decompilation.addProperty("diagnostic", decoded.getErrorMessage());
            String c = null;
            if (decoded.decompileCompleted() && decoded.getDecompiledFunction() != null) {
                c = decoded.getDecompiledFunction().getC();
                require(c.getBytes(StandardCharsets.UTF_8).length <= 262144, "C output exceeds budget");
                decompilation.addProperty("signature", decoded.getDecompiledFunction().getSignature());
            }
            JsonArray high = new JsonArray(); Set<Address> outside = new TreeSet<>();
            if (decoded.getHighFunction() != null) {
                Iterator<PcodeOpAST> operations = decoded.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    checkBudget(); require(high.size() < 16384, "High p-code budget exceeded");
                    PcodeOpAST operation = operations.next(); Address pc = operation.getSeqnum().getTarget();
                    if (!body.contains(pc)) outside.add(pc);
                    high.add(pcode(operation,address(pc),operation.getSeqnum().getTime()));
                }
            }
            json(label + ".high-pcode.json", high); decompilation.addProperty("high_pcode_count", high.size());
            JsonArray outsideAddresses = new JsonArray(); for (Address pc : outside) outsideAddresses.add(address(pc));
            decompilation.add("outside_body_pcs", outsideAddresses);
            decompilation.addProperty("scope_accepted", outside.isEmpty());
            decompilation.addProperty("frontend_address_restriction", "The public decompiler may recover code beyond Function.body; every high-pcode PC is independently checked against the bounded listing body.");
            if (!outside.isEmpty()) {
                result.addProperty("status", "scope_rejected"); result.addProperty("error_code", "DECOMPILER_SCOPE_ESCAPE");
                if (c != null) { write(label + ".scope-rejected.c",c); decompilation.addProperty("unaccepted_c_file",label + ".scope-rejected.c"); }
            } else if (c != null) {
                result.addProperty("status", "observed"); write(label + ".c",c); decompilation.addProperty("c_file",label + ".c");
            } else {
                result.addProperty("status", "decompile_incomplete");
            }
        } finally { decompiler.dispose(); }
        result.addProperty("duration_ms", TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started));
        json(label + ".json", result); println("WIREFIT_BOUNDED_FUNCTION " + label + " instructions=" + listing.size());
        return result;
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs(); require(args.length == 2, "Expected request JSON and owned output directory");
        Path requestPath = Path.of(args[0]).toRealPath(); output = Path.of(args[1]).toRealPath();
        require(Files.isDirectory(output) && !Files.isSymbolicLink(output), "Expected existing regular output directory");
        require(Files.size(requestPath) <= 32768, "Request exceeds budget");
        JsonObject request = JsonParser.parseString(Files.readString(requestPath,StandardCharsets.UTF_8)).getAsJsonObject();
        keys(request,"schema_version","expected_sha256","entries","decompile_seconds","script_seconds");
        require(integer(request.get("schema_version"),1,1)==1,"Unsupported protocol");
        decompileSeconds=integer(request.get("decompile_seconds"),1,5);
        int scriptSeconds=integer(request.get("script_seconds"),1,45);
        deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(scriptSeconds);
        String expected=request.get("expected_sha256").getAsString();
        require(expected.matches("[a-f0-9]{64}") && expected.equals(currentProgram.getExecutableSHA256()),"Imported file digest mismatch");
        JsonArray selected=request.getAsJsonArray("entries"); require(selected.size()>0&&selected.size()<=5,"At most five selected functions");
        for (JsonElement item:selected) {
            JsonObject value=item.getAsJsonObject(); keys(value,"va","max_bytes");
            String text=value.get("va").getAsString(); require(text.matches("0x[0-9a-fA-F]{1,8}"),"Invalid selected VA");
            require(entries.add(toAddr(text)),"Duplicate selected entry"); integer(value.get("max_bytes"),1,2048);
        }
        enableHeadlessAnalysis(false); currentProgram.setTemporary(true);
        JsonObject summary=new JsonObject(); summary.addProperty("schema_version",1); summary.addProperty("provider","ghidra-public-bounded-static");
        summary.addProperty("ghidra_version",Application.getApplicationVersion()); summary.addProperty("input_sha256",expected);
        summary.addProperty("language",currentProgram.getLanguageID().toString()); summary.addProperty("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        summary.addProperty("image_base",address(currentProgram.getImageBase())); summary.addProperty("auto_analysis",false);
        summary.addProperty("script_seconds",scriptSeconds); summary.addProperty("target_executed",false); summary.add("request",request);
        JsonArray results=new JsonArray(); summary.add("functions",results);
        for (JsonElement item:selected) {
            JsonObject value=item.getAsJsonObject(); Address entry=toAddr(value.get("va").getAsString());
            try { results.add(analyze(entry,integer(value.get("max_bytes"),1,2048))); }
            catch(Exception error) {
                JsonObject failure=new JsonObject(); failure.addProperty("entry_va",address(entry)); failure.addProperty("status","failed");
                failure.addProperty("error",error.getClass().getName()+": "+error.getMessage()); results.add(failure);
                println("WIREFIT_BOUNDED_FUNCTION_FAILED "+entry+" "+error);
            }
        }
        boolean allScopesObserved = true;
        for (JsonElement item : results) {
            JsonObject value = item.getAsJsonObject();
            if (!value.has("status") || !"observed".equals(value.get("status").getAsString())) allScopesObserved = false;
        }
        summary.addProperty("status",allScopesObserved ? "completed" : "partial");
        summary.addProperty("elapsed_script_ms",TimeUnit.NANOSECONDS.toMillis(TimeUnit.SECONDS.toNanos(scriptSeconds)-(deadline-System.nanoTime())));
        json("summary.json",summary); println("WIREFIT_BOUNDED_COMPLETED");
    }
}

