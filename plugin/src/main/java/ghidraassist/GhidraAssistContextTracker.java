package ghidraassist;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tracks the user's current location and selection in Ghidra's CodeBrowser.
 * Maintains context about the current function, address, decompiled source,
 * and any selected bytes/text. The context is sent with chat messages so the
 * LLM has situational awareness of what the analyst is looking at.
 *
 * Decompilation is performed asynchronously and debounced so that rapid cursor
 * movements within the same function do not trigger redundant decompiles.
 */
public class GhidraAssistContextTracker {

    private Program currentProgram;
    private ProgramLocation currentLocation;
    private ProgramSelection currentSelection;

    /** Cache of function entry address -> decompiled C source */
    private final ConcurrentHashMap<Address, String> decompileCache = new ConcurrentHashMap<>();

    /** The function that was last decompiled (for debounce comparison) */
    private final AtomicReference<Address> lastDecompiledFunctionAddr = new AtomicReference<>();

    /** Single-threaded executor for background decompilation */
    private final ExecutorService decompileExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "GhidraAssist-Decompiler");
        t.setDaemon(true);
        return t;
    });

    /** Optional callback fired when context changes (e.g. to update UI indicators) */
    private ContextChangeCallback changeCallback;

    @FunctionalInterface
    public interface ContextChangeCallback {
        void onContextChanged(Map<String, String> newContext);
    }

    /**
     * Set the callback to be fired when context changes.
     */
    public void setContextChangeCallback(ContextChangeCallback callback) {
        this.changeCallback = callback;
    }

    public GhidraAssistContextTracker() {
        // default constructor
    }

    // --- Program lifecycle ---

    public void setProgram(Program program) {
        this.currentProgram = program;
        decompileCache.clear();
        lastDecompiledFunctionAddr.set(null);
    }

    public void clearProgram() {
        this.currentProgram = null;
        this.currentLocation = null;
        this.currentSelection = null;
        decompileCache.clear();
        lastDecompiledFunctionAddr.set(null);
    }

    // --- Location tracking ---

    /**
     * Called when the user's cursor location changes in the listing or decompiler.
     */
    public void locationChanged(ProgramLocation location) {
        if (location == null) {
            return;
        }
        this.currentLocation = location;

        if (currentProgram != null) {
            Address addr = location.getAddress();
            if (addr != null) {
                FunctionManager fm = currentProgram.getFunctionManager();
                Function func = fm.getFunctionContaining(addr);
                if (func != null) {
                    Address entry = func.getEntryPoint();
                    // Debounce: only decompile if we moved to a different function
                    if (!entry.equals(lastDecompiledFunctionAddr.get())) {
                        lastDecompiledFunctionAddr.set(entry);
                        scheduleDecompile(func);
                    }
                }
            }
        }

        fireContextChanged();
    }

    /**
     * Called when the user's selection changes.
     */
    public void selectionChanged(ProgramSelection selection) {
        this.currentSelection = selection;
        fireContextChanged();
    }

    // --- Context assembly ---

    /**
     * Builds a context map suitable for sending with a chat message.
     *
     * @param mode "function", "selection", or "both"
     * @return map of context fields (null values omitted)
     */
    public Map<String, String> getContext(String mode) {
        Map<String, String> ctx = new LinkedHashMap<>();

        if (currentProgram != null) {
            ctx.put("program", currentProgram.getName());
            // Use project/repository name so tools can resolve the Ghidra Server repo
            String repoName = currentProgram.getDomainFile().getProjectLocator().getName();
            ctx.put("repo", repoName);
        }

        if (currentLocation != null) {
            Address addr = currentLocation.getAddress();
            if (addr != null) {
                ctx.put("address", addr.toString());
            }
        }

        boolean includeFunction = "function".equals(mode) || "both".equals(mode);
        boolean includeSelection = "selection".equals(mode) || "both".equals(mode);

        if (includeFunction) {
            addFunctionContext(ctx);
        }

        if (includeSelection) {
            addSelectionContext(ctx);
        }

        return ctx;
    }

    /**
     * Convenience overload using default mode "function".
     */
    public Map<String, String> getContext() {
        return getContext("function");
    }

    /**
     * Calculate the total size in bytes of all context fields.
     * Used to show context size indicators in the UI.
     */
    public long getTotalContextSize(String mode) {
        Map<String, String> context = getContext(mode);
        long total = 0;
        for (String value : context.values()) {
            if (value != null) {
                total += value.getBytes().length;
            }
        }
        return total;
    }

    /**
     * Convenience overload using default mode "function".
     */
    public long getTotalContextSize() {
        return getTotalContextSize("function");
    }

    // --- Decompilation ---

    private void scheduleDecompile(Function function) {
        Address entry = function.getEntryPoint();
        // Skip if already cached
        if (decompileCache.containsKey(entry)) {
            return;
        }

        Program program = currentProgram;
        if (program == null) {
            return;
        }

        decompileExecutor.submit(() -> {
            try {
                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(program);
                    DecompileResults results = decomp.decompileFunction(function,
                            30, new ConsoleTaskMonitor());
                    if (results != null && results.decompileCompleted()) {
                        String cCode = results.getDecompiledFunction().getC();
                        if (cCode != null && !cCode.isBlank()) {
                            decompileCache.put(entry, cCode);
                            fireContextChanged();
                        }
                    }
                } finally {
                    decomp.dispose();
                }
            } catch (Exception e) {
                Msg.warn(this, "Decompilation failed for " + entry + ": " + e.getMessage());
            }
        });
    }

    // --- Internal helpers ---

    private void addFunctionContext(Map<String, String> ctx) {
        if (currentProgram == null || currentLocation == null) {
            return;
        }
        Address addr = currentLocation.getAddress();
        if (addr == null) {
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionContaining(addr);
        if (func == null) {
            return;
        }

        ctx.put("function", func.getName());
        ctx.put("function_address", func.getEntryPoint().toString());
        ctx.put("function_signature", func.getPrototypeString(true, false));

        // Include decompiled source if cached
        String decompiled = decompileCache.get(func.getEntryPoint());
        if (decompiled != null) {
            ctx.put("decompilation", decompiled);
        }
    }

    private void addSelectionContext(Map<String, String> ctx) {
        if (currentSelection == null || currentSelection.isEmpty()) {
            return;
        }
        if (currentProgram == null) {
            return;
        }

        Address minAddr = currentSelection.getMinAddress();
        Address maxAddr = currentSelection.getMaxAddress();
        ctx.put("selection_start", minAddr.toString());
        ctx.put("selection_end", maxAddr.toString());
        ctx.put("selection_size", String.valueOf(currentSelection.getNumAddresses()));

        // Read selected bytes (cap at 4096 to avoid huge payloads)
        try {
            long numBytes = Math.min(currentSelection.getNumAddresses(), 4096);
            byte[] bytes = new byte[(int) numBytes];
            int read = currentProgram.getMemory().getBytes(minAddr, bytes);
            if (read > 0) {
                StringBuilder hex = new StringBuilder(read * 3);
                for (int i = 0; i < read; i++) {
                    if (i > 0) {
                        hex.append(' ');
                    }
                    hex.append(String.format("%02x", bytes[i] & 0xFF));
                }
                ctx.put("selection_bytes", hex.toString());
            }
        } catch (Exception e) {
            // Memory read can fail for various reasons; non-fatal
            Msg.debug(this, "Could not read selection bytes: " + e.getMessage());
        }
    }

    private void fireContextChanged() {
        if (changeCallback != null) {
            changeCallback.onContextChanged(getContext());
        }
    }

    public void setChangeCallback(ContextChangeCallback callback) {
        this.changeCallback = callback;
    }

    /**
     * Releases resources. Call when the plugin is disposed.
     */
    public void dispose() {
        decompileExecutor.shutdownNow();
        decompileCache.clear();
    }
}
