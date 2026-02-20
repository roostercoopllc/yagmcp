/* ###
 * IP: GHIDRA
 *
 * Licensed under the MIT License.
 * SPDX-License-Identifier: MIT
 * ###
 */
package ghidraassist;

import javax.swing.JComponent;

import docking.ComponentProvider;
import ghidra.program.model.listing.Program;
import ghidraassist.ui.ChatPanel;

/**
 * ComponentProvider that hosts the YAGMCP chat panel as a dockable
 * window in Ghidra's tool framework.
 *
 * <p>The panel appears in Ghidra's window system and can be docked,
 * undocked, or closed like any other Ghidra component.</p>
 */
public class GhidraAssistProvider extends ComponentProvider {

    private final GhidraAssistPlugin plugin;
    private final GhidraAssistContextTracker contextTracker;
    private final ChatPanel chatPanel;

    public GhidraAssistProvider(GhidraAssistPlugin plugin,
            GhidraAssistContextTracker contextTracker) {
        super(plugin.getTool(), "YAGMCP", plugin.getName());

        this.plugin = plugin;
        this.contextTracker = contextTracker;

        setTitle("YAGMCP");
        setDefaultWindowPosition(docking.WindowPosition.RIGHT);
        setVisible(true);

        // Build the chat panel
        GhidraAssistSettings settings = new GhidraAssistSettings(plugin.getTool());
        GhidraAssistClient client = new GhidraAssistClient(settings.getServerUrl(), settings.getModelName());
        chatPanel = new ChatPanel(settings, client, contextTracker);

        // Show initial system message
        chatPanel.addMessage("system", "YAGMCP ready. Open a program and start chatting.");
    }

    @Override
    public JComponent getComponent() {
        return chatPanel;
    }

    /**
     * Called when a program is opened.
     */
    public void programOpened(Program program) {
        chatPanel.addMessage("system","Program opened: " + program.getName());
    }

    /**
     * Called when a program is closed.
     */
    public void programClosed(Program program) {
        chatPanel.addMessage("system","Program closed: " + program.getName());
    }

    /**
     * Called when the active program changes.
     */
    public void programActivated(Program program) {
        chatPanel.addMessage("system","Active program: " + program.getName());
    }

    /**
     * Clean up resources.
     */
    public void dispose() {
        // ChatPanel extends JPanel — no explicit disposal needed
    }
}
