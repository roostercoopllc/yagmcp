/* ###
 * IP: GHIDRA
 *
 * Licensed under the MIT License.
 * SPDX-License-Identifier: MIT
 * ###
 */
package ghidraassist;

import javax.swing.JComponent;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import docking.ComponentProvider;
import ghidra.program.model.listing.Program;
import ghidraassist.ui.ChatPanel;
import ghidraassist.ui.CallGraphPanel;

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
    private final CallGraphPanel callGraphPanel;
    private final JTabbedPane tabbedPane;

    public GhidraAssistProvider(GhidraAssistPlugin plugin,
            GhidraAssistContextTracker contextTracker) {
        super(plugin.getTool(), "YAGMCP", plugin.getName());

        this.plugin = plugin;
        this.contextTracker = contextTracker;

        setTitle("YAGMCP");
        setDefaultWindowPosition(docking.WindowPosition.RIGHT);
        setVisible(true);

        // Build the chat panel (pass plugin tool for auto-reload capability)
        GhidraAssistSettings settings = new GhidraAssistSettings(plugin.getTool());
        GhidraAssistClient client = new GhidraAssistClient(settings.getServerUrl(), settings.getModelName(), settings.getRequestTimeout());
        chatPanel = new ChatPanel(settings, client, contextTracker, plugin.getTool());

        // Show initial system message
        chatPanel.addMessage("system", "YAGMCP ready. Open a program and start chatting.");

        // Build the call graph panel
        callGraphPanel = new CallGraphPanel(chatPanel);

        // Create tabbed pane with Chat and Call Graph tabs
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Chat", chatPanel);
        tabbedPane.addTab("Call Graph", callGraphPanel);

        // Set up keyboard shortcuts
        setupKeyboardShortcuts();
    }

    /**
     * Set up keyboard shortcuts for common actions.
     */
    private void setupKeyboardShortcuts() {
        tabbedPane.addKeyListener(new KeyListener() {
            @Override
            public void keyPressed(KeyEvent e) {
                // Ctrl+Tab: Next tab
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_TAB && !e.isShiftDown()) {
                    int current = tabbedPane.getSelectedIndex();
                    int next = (current + 1) % tabbedPane.getTabCount();
                    tabbedPane.setSelectedIndex(next);
                    e.consume();
                }
                // Ctrl+Shift+Tab: Previous tab
                else if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_TAB && e.isShiftDown()) {
                    int current = tabbedPane.getSelectedIndex();
                    int prev = (current - 1 + tabbedPane.getTabCount()) % tabbedPane.getTabCount();
                    tabbedPane.setSelectedIndex(prev);
                    e.consume();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {}

            @Override
            public void keyTyped(KeyEvent e) {}
        });

        tabbedPane.setFocusable(true);
    }

    @Override
    public JComponent getComponent() {
        return tabbedPane;
    }

    /**
     * Called when a program is opened.
     */
    public void programOpened(Program program) {
        chatPanel.setCurrentProgram(program);
        chatPanel.addMessage("system","Program opened: " + program.getName());
        callGraphPanel.updateFunctionList(program);
    }

    /**
     * Called when a program is closed.
     */
    public void programClosed(Program program) {
        chatPanel.setCurrentProgram(null);
        chatPanel.addMessage("system","Program closed: " + program.getName());
        callGraphPanel.clear();
    }

    /**
     * Called when the active program changes.
     */
    public void programActivated(Program program) {
        chatPanel.setCurrentProgram(program);
        chatPanel.addMessage("system","Active program: " + program.getName());
        callGraphPanel.updateFunctionList(program);
    }

    /**
     * Clean up resources.
     */
    public void dispose() {
        // ChatPanel extends JPanel — no explicit disposal needed
    }
}
