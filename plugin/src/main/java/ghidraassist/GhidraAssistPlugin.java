/* ###
 * IP: GHIDRA
 *
 * Licensed under the MIT License.
 * SPDX-License-Identifier: MIT
 * ###
 */
package ghidraassist;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

/**
 * YAGMCP — LLM-assisted reverse engineering chat panel.
 *
 * <p>This plugin provides an embedded chat panel in the CodeBrowser that
 * connects to a remote YAGMCP server for headless Ghidra analysis
 * powered by Ollama (or any compatible LLM).</p>
 *
 * <p>The plugin tracks the current function, address, and selection,
 * automatically sending context with each chat message so the LLM
 * knows what you're looking at.</p>
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "YAGMCP",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "LLM-assisted reverse engineering",
    description = "Embedded chat panel connecting to a YAGMCP server for " +
        "context-aware LLM analysis of Ghidra programs. Supports Ollama, " +
        "Claude Desktop, and Open WebUI backends."
)
//@formatter:on
public class GhidraAssistPlugin extends ProgramPlugin {

    private GhidraAssistProvider provider;
    private GhidraAssistContextTracker contextTracker;

    public GhidraAssistPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();

        contextTracker = new GhidraAssistContextTracker();
        provider = new GhidraAssistProvider(this, contextTracker);
    }

    @Override
    protected void programOpened(Program program) {
        contextTracker.setProgram(program);
        provider.programOpened(program);
    }

    @Override
    protected void programClosed(Program program) {
        contextTracker.clearProgram();
        provider.programClosed(program);
    }

    @Override
    protected void programActivated(Program program) {
        contextTracker.setProgram(program);
        provider.programActivated(program);
    }

    @Override
    protected void locationChanged(ghidra.program.util.ProgramLocation loc) {
        if (loc != null) {
            contextTracker.locationChanged(loc);
        }
    }

    @Override
    protected void selectionChanged(ghidra.program.util.ProgramSelection sel) {
        if (sel != null) {
            contextTracker.selectionChanged(sel);
        }
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
        }
        super.dispose();
    }

    /**
     * Get the context tracker for use by the provider and client.
     */
    public GhidraAssistContextTracker getContextTracker() {
        return contextTracker;
    }
}
