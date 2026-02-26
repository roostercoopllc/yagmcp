package ghidraassist.ui;

import ghidraassist.GhidraAssistClient;
import ghidraassist.GhidraAssistClient.ChatResponse;
import ghidraassist.GhidraAssistContextTracker;
import ghidraassist.GhidraAssistSettings;
import ghidraassist.GhidraAssistSettings.ColorPalette;
import ghidraassist.ChangeTracker;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.border.LineBorder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * The main chat panel embedded in Ghidra's dockable window.
 *
 * Supports hot-reload: when MCP tools modify a program, the decompiler and
 * listing views automatically refresh to show the changes without manual reload.
 *
 * Layout:
 * <pre>
 *  +----------------------------------------------+
 *  | [Model ▼]  [● Connected]            [⚙]     |  <- top bar
 *  +----------------------------------------------+
 *  |                                              |
 *  |  Message bubbles (scrollable)                |  <- center
 *  |                                              |
 *  +----------------------------------------------+
 *  | [Context ▼] [ message input ...       ] [>>] |  <- bottom bar
 *  +----------------------------------------------+
 * </pre>
 */
public class ChatPanel extends JPanel {

    // Status colors (constant across all palettes)
    private static final Color STATUS_CONNECTED = new Color(0, 200, 0);
    private static final Color STATUS_DISCONNECTED = new Color(200, 0, 0);
    private static final Color STATUS_CHECKING = new Color(200, 200, 0);

    private final GhidraAssistSettings settings;
    private final GhidraAssistClient client;
    private final GhidraAssistContextTracker contextTracker;
    private final ChangeTracker changeTracker = new ChangeTracker();
    private final PluginTool tool;
    private Program currentProgram;

    // Colors from current palette (initialized in constructor)
    private Color PANEL_BG;
    private Color INPUT_BG;
    private Color INPUT_FG;
    private Color BAR_BG;

    // Top bar
    private JPanel changeNotificationPanel;
    private JLabel changeCountLabel;
    private JButton reloadButton;
    private JComboBox<String> modelSelector;
    private JLabel statusDot;
    private JLabel statusText;
    private JButton settingsButton;

    // Message area
    private ScrollablePanel messagesPanel;
    private JScrollPane messagesScroll;

    // Bottom bar
    private JComboBox<String> contextModeSelector;
    private JTextField inputField;
    private JButton sendButton;
    private JLabel contextSizeLabel;

    // State
    private final List<MessageEntry> messageHistory = new ArrayList<>();
    private boolean isSending = false;

    public ChatPanel(GhidraAssistSettings settings, GhidraAssistClient client,
            GhidraAssistContextTracker contextTracker, PluginTool tool) {
        this.settings = settings;
        this.client = client;
        this.contextTracker = contextTracker;
        this.tool = tool;
        this.currentProgram = null; // Will be set when program opens

        // Initialize colors from the selected palette
        applyColorPalette(settings.getColorPalette());

        setLayout(new BorderLayout());
        setBackground(PANEL_BG);

        buildChangeNotificationPanel();
        buildTopBar();
        buildMessageArea();
        buildBottomBar();

        // Wire context tracker callback to update context size display
        contextTracker.setContextChangeCallback(ctx -> {
            String currentMode = (String) contextModeSelector.getSelectedItem();
            if (currentMode != null) {
                updateContextSizeDisplay(currentMode);
            }
        });

        // Initial context size display
        String initialMode = (String) contextModeSelector.getSelectedItem();
        if (initialMode != null) {
            updateContextSizeDisplay(initialMode);
        }

        // Initial connection check
        checkConnection();

        // System welcome message
        addMessage("system", "YAGMCP ready. Connected to " + settings.getServerUrl()
                + " using model " + settings.getModelName() + ".");
    }

    // ========== UI Construction ==========

    private void buildTopBar() {
        JPanel topBar = new JPanel(new BorderLayout(8, 0));
        topBar.setBackground(BAR_BG);
        topBar.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Left: model selector
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        leftPanel.setOpaque(false);

        JLabel modelLabel = new JLabel("Model:");
        modelLabel.setForeground(INPUT_FG);
        leftPanel.add(modelLabel);

        modelSelector = new JComboBox<>(new String[]{settings.getModelName()});
        modelSelector.setEditable(true);
        modelSelector.setSelectedItem(settings.getModelName());
        modelSelector.setPreferredSize(new Dimension(180, 26));
        modelSelector.addActionListener(e -> {
            String selected = (String) modelSelector.getSelectedItem();
            if (selected != null && !selected.isBlank()) {
                client.setModel(selected);
                settings.setModelName(selected);
            }
        });
        leftPanel.add(modelSelector);

        topBar.add(leftPanel, BorderLayout.WEST);

        // Center: connection status
        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 0));
        centerPanel.setOpaque(false);

        statusDot = new JLabel("\u25CF");  // filled circle
        statusDot.setForeground(STATUS_CHECKING);
        statusDot.setFont(statusDot.getFont().deriveFont(10f));
        centerPanel.add(statusDot);

        statusText = new JLabel("Checking...");
        statusText.setForeground(INPUT_FG);
        statusText.setFont(statusText.getFont().deriveFont(11f));
        centerPanel.add(statusText);

        topBar.add(centerPanel, BorderLayout.CENTER);

        // Right: settings gear
        settingsButton = new JButton("\u2699");  // gear symbol
        settingsButton.setFont(settingsButton.getFont().deriveFont(16f));
        settingsButton.setFocusPainted(false);
        settingsButton.setContentAreaFilled(false);
        settingsButton.setForeground(INPUT_FG);
        settingsButton.setBorder(new EmptyBorder(2, 8, 2, 8));
        settingsButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        settingsButton.setToolTipText("Settings");
        settingsButton.addActionListener(e -> openSettings());

        topBar.add(settingsButton, BorderLayout.EAST);

        // Create a wrapper panel for change notification + top bar
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(BAR_BG);
        headerPanel.add(changeNotificationPanel, BorderLayout.NORTH);
        headerPanel.add(topBar, BorderLayout.CENTER);

        add(headerPanel, BorderLayout.NORTH);
    }

    private void buildChangeNotificationPanel() {
        changeNotificationPanel = new JPanel(new BorderLayout(10, 0));
        changeNotificationPanel.setBackground(new Color(80, 60, 0));  // Dark orange/gold
        changeNotificationPanel.setBorder(new EmptyBorder(6, 10, 6, 10));
        changeNotificationPanel.setVisible(false);

        JLabel warningIcon = new JLabel("⚠");
        warningIcon.setFont(warningIcon.getFont().deriveFont(14f));
        warningIcon.setForeground(new Color(255, 200, 0));
        changeNotificationPanel.add(warningIcon, BorderLayout.WEST);

        JPanel centerPanel = new JPanel(new BorderLayout(10, 0));
        centerPanel.setOpaque(false);

        changeCountLabel = new JLabel();
        changeCountLabel.setForeground(new Color(255, 255, 200));
        changeCountLabel.setFont(changeCountLabel.getFont().deriveFont(Font.BOLD));
        centerPanel.add(changeCountLabel, BorderLayout.CENTER);

        reloadButton = new JButton("Reload Program");
        reloadButton.setBackground(new Color(60, 120, 60));
        reloadButton.setForeground(Color.WHITE);
        reloadButton.setFocusPainted(false);
        reloadButton.setBorder(new LineBorder(new Color(100, 200, 100), 1));
        reloadButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        reloadButton.addActionListener(e -> reloadProgram());
        reloadButton.setToolTipText("Reload the program from disk to see changes");
        centerPanel.add(reloadButton, BorderLayout.EAST);

        changeNotificationPanel.add(centerPanel, BorderLayout.CENTER);
    }

    private void reloadProgram() {
        if (currentProgram == null) {
            addMessage("system", "No program is currently open.");
            return;
        }

        try {
            // Flush events to disk (Ghidra 12.0.3)
            try {
                if (currentProgram != null) {
                    currentProgram.flushEvents();
                    addMessage("system", "✓ Program events flushed. Changes are now visible.");
                }
            } catch (Exception e) {
                addMessage("system", "Error flushing program: " + e.getMessage());
            }

            changeTracker.clearChanges();
            updateChangeNotification();

        } catch (Exception e) {
            addMessage("system", "Reload error: " + e.getMessage());
        }
    }

    private void updateChangeNotification() {
        if (changeTracker.hasChanges()) {
            List<ChangeTracker.Change> changes = changeTracker.getChanges();
            changeCountLabel.setText(changes.size() + " modification(s) detected.");
            changeNotificationPanel.setVisible(true);

            // Auto-reload if enabled: trigger reload automatically after a brief delay
            // This allows the server to finish writing changes to disk before we reload
            if (settings.isAutoReload()) {
                new Thread(() -> {
                    try {
                        Thread.sleep(500);  // Wait for server to finish writing
                        SwingUtilities.invokeLater(() -> {
                            reloadProgram();
                            addMessage("system", "✓ Auto-reload completed (hot-reload enabled)");
                        });
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }).start();
            } else {
                // Manual reload mode: show message with reload button
                addMessage("system", "Program modified. Changes will be visible when you reload.\n" +
                        "Click 'Reload' in the notification banner or press File > Reopen File.");
            }
        } else {
            changeNotificationPanel.setVisible(false);
        }
        changeNotificationPanel.revalidate();
        changeNotificationPanel.repaint();
    }

    /**
     * Update the current program reference (called by provider when program changes).
     */
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
    }

    /**
     * Apply a color palette to the chat panel UI.
     */
    public void applyColorPalette(ColorPalette palette) {
        this.PANEL_BG = palette.panelBg;
        this.INPUT_BG = palette.inputBg;
        this.INPUT_FG = palette.inputFg;
        this.BAR_BG = palette.barBg;

        // Update existing components if they exist
        setBackground(PANEL_BG);
        if (messagesPanel != null) {
            messagesPanel.setBackground(PANEL_BG);
        }
        if (inputField != null) {
            inputField.setBackground(INPUT_BG);
            inputField.setForeground(INPUT_FG);
        }
        repaint();
    }

    private void buildMessageArea() {
        messagesPanel = new ScrollablePanel();
        messagesPanel.setLayout(new BoxLayout(messagesPanel, BoxLayout.Y_AXIS));
        messagesPanel.setBackground(PANEL_BG);
        messagesPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

        messagesScroll = new JScrollPane(messagesPanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        messagesScroll.setBorder(null);
        messagesScroll.getViewport().setBackground(PANEL_BG);
        messagesScroll.getVerticalScrollBar().setUnitIncrement(16);

        add(messagesScroll, BorderLayout.CENTER);
    }

    private void buildBottomBar() {
        JPanel bottomBar = new JPanel(new BorderLayout(6, 0));
        bottomBar.setBackground(BAR_BG);
        bottomBar.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Left: context mode selector + context size indicator
        JPanel leftPanel = new JPanel(new BorderLayout(4, 0));
        leftPanel.setBackground(BAR_BG);

        contextModeSelector = new JComboBox<>(new String[]{"function", "selection", "both", "none"});
        contextModeSelector.setSelectedItem(settings.getContextMode());
        contextModeSelector.setPreferredSize(new Dimension(100, 26));
        contextModeSelector.setToolTipText("Context to include with messages");
        contextModeSelector.addActionListener(e -> {
            String mode = (String) contextModeSelector.getSelectedItem();
            if (mode != null) {
                settings.setContextMode(mode);
                updateContextSizeDisplay(mode);
            }
        });
        leftPanel.add(contextModeSelector, BorderLayout.WEST);

        // Context size indicator
        contextSizeLabel = new JLabel("Context: 0B");
        contextSizeLabel.setForeground(INPUT_FG);
        contextSizeLabel.setFont(contextSizeLabel.getFont().deriveFont(11f));
        contextSizeLabel.setToolTipText("Total size of context being sent to server");
        leftPanel.add(contextSizeLabel, BorderLayout.CENTER);

        bottomBar.add(leftPanel, BorderLayout.WEST);

        // Center: text input
        inputField = new JTextField();
        inputField.setBackground(INPUT_BG);
        inputField.setForeground(INPUT_FG);
        inputField.setCaretColor(INPUT_FG);
        inputField.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        inputField.setBorder(new CompoundBorder(
                new LineBorder(new Color(60, 60, 60), 1, true),
                new EmptyBorder(4, 8, 4, 8)));

        // Enter key sends message
        inputField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "send");
        inputField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK), "send");
        inputField.getActionMap().put("send", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        bottomBar.add(inputField, BorderLayout.CENTER);

        // Right: send button
        sendButton = new JButton("\u25B6");  // right-pointing triangle
        sendButton.setFont(sendButton.getFont().deriveFont(14f));
        sendButton.setFocusPainted(false);
        sendButton.setToolTipText("Send message");
        sendButton.setPreferredSize(new Dimension(50, 26));
        sendButton.addActionListener(e -> sendMessage());

        bottomBar.add(sendButton, BorderLayout.EAST);

        add(bottomBar, BorderLayout.SOUTH);
    }

    // ========== Actions ==========

    /**
     * Send a query from the call graph panel or other components.
     * Populates the input field and triggers message sending.
     */
    public void sendQuery(String query) {
        SwingUtilities.invokeLater(() -> {
            inputField.setText(query);
            sendMessage();
        });
    }

    private void sendMessage() {
        String text = inputField.getText().trim();
        if (text.isEmpty() || isSending) {
            return;
        }

        // Special commands
        if (text.equalsIgnoreCase("/clear")) {
            clearMessages();
            inputField.setText("");
            return;
        }
        if (text.equalsIgnoreCase("/reset")) {
            client.resetConversation();
            clearMessages();
            addMessage("system", "Conversation reset. New conversation ID: "
                    + client.getConversationId());
            inputField.setText("");
            return;
        }
        if (text.equalsIgnoreCase("/status")) {
            checkConnection();
            inputField.setText("");
            return;
        }

        // Display user message
        addMessage("user", text);
        inputField.setText("");

        // Gather context
        Map<String, String> context = null;
        String contextMode = (String) contextModeSelector.getSelectedItem();
        if (settings.isAutoIncludeContext() && !"none".equals(contextMode)) {
            context = contextTracker.getContext(contextMode);
        }

        // Send asynchronously
        isSending = true;
        setSendingState(true);

        final Map<String, String> finalContext = context;
        client.sendMessageAsync(text, finalContext).thenAccept(response -> {
            SwingUtilities.invokeLater(() -> {
                isSending = false;
                setSendingState(false);

                if (response.isError()) {
                    addMessage("system", "Error: " + response.getErrorMessage());
                } else {
                    addMessage("assistant", response.getContent());

                    // Track tools that were called (modification tools)
                    for (String toolName : response.getToolsCalled()) {
                        if (isModificationTool(toolName)) {
                            // Try to extract change details from raw response
                            Map<String, Object> rawResponse = response.getRawResponse();
                            changeTracker.trackToolResponse(toolName, rawResponse);
                        }
                    }

                    // Update change notification if any modifications were made
                    if (!response.getToolsCalled().isEmpty()) {
                        updateChangeNotification();
                    }

                    // Execute client-side directives (e.g. rename_variable)
                    Map<String, Object> raw = response.getRawResponse();
                    Object directivesObj = raw.get("directives");
                    if (directivesObj instanceof List<?>) {
                        executeDirectives((List<?>) directivesObj);
                    }
                }
            });
        }).exceptionally(ex -> {
            SwingUtilities.invokeLater(() -> {
                isSending = false;
                setSendingState(false);
                addMessage("system", "Error: " + ex.getMessage());
            });
            return null;
        });
    }

    /**
     * Execute client-side directives returned by the server.
     * Runs rename_variable directly in the Ghidra JVM so changes are
     * immediately visible in the decompiler without Ghidra-server conflicts.
     */
    @SuppressWarnings("unchecked")
    private void executeDirectives(List<?> directives) {
        if (currentProgram == null || directives.isEmpty()) {
            return;
        }

        // Collect rename directives
        List<Map<String, String>> renames = new ArrayList<>();
        for (Object d : directives) {
            if (d instanceof Map) {
                Map<String, Object> directive = (Map<String, Object>) d;
                if ("rename_variable".equals(directive.get("action"))) {
                    Map<String, String> rename = new java.util.HashMap<>();
                    rename.put("old_name", String.valueOf(directive.getOrDefault("old_name", "")));
                    rename.put("new_name", String.valueOf(directive.getOrDefault("new_name", "")));
                    rename.put("function", String.valueOf(directive.getOrDefault("function", "")));
                    renames.add(rename);
                }
            }
        }

        if (renames.isEmpty()) {
            return;
        }

        // Run on a background thread to avoid blocking the UI during decompilation
        new Thread(() -> {
            int applied = 0;
            int failed = 0;

            // Find the target function
            String funcName = renames.get(0).get("function");
            FunctionManager fm = currentProgram.getFunctionManager();
            Function targetFunc = null;
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(funcName)) {
                    targetFunc = f;
                    break;
                }
            }

            if (targetFunc == null) {
                final String msg = "Could not find function '" + funcName + "' to apply renames.";
                SwingUtilities.invokeLater(() -> addMessage("system", msg));
                return;
            }

            // Decompile once to get the HighFunction with all variables
            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(currentProgram);
                DecompileResults decompResult = decomp.decompileFunction(
                        targetFunc, 60, new ConsoleTaskMonitor());

                if (decompResult == null || decompResult.getHighFunction() == null) {
                    SwingUtilities.invokeLater(() ->
                            addMessage("system", "Decompilation failed; cannot apply renames."));
                    return;
                }

                var highFunc = decompResult.getHighFunction();
                var localMap = highFunc.getLocalSymbolMap();

                // Apply each rename in a single transaction
                int txid = currentProgram.startTransaction("Rename variables");
                try {
                    for (Map<String, String> r : renames) {
                        String oldName = r.get("old_name");
                        String newName = r.get("new_name");

                        // Search high-level symbols (local variables + parameters)
                        HighSymbol target = null;
                        var symIter = localMap.getSymbols();
                        while (symIter.hasNext()) {
                            HighSymbol sym = symIter.next();
                            if (sym.getName().equals(oldName)) {
                                target = sym;
                                break;
                            }
                        }

                        // Also check function parameters
                        if (target == null) {
                            boolean foundParam = false;
                            for (var param : targetFunc.getParameters()) {
                                if (param.getName().equals(oldName)) {
                                    try {
                                        param.setName(newName, SourceType.USER_DEFINED);
                                        applied++;
                                        foundParam = true;
                                    } catch (Exception e) {
                                        failed++;
                                        foundParam = true; // don't double-count
                                    }
                                    break;
                                }
                            }
                            if (!foundParam) {
                                failed++;
                            }
                            continue;
                        }

                        try {
                            HighFunctionDBUtil.updateDBVariable(
                                    target, newName, null, SourceType.USER_DEFINED);
                            applied++;
                        } catch (Exception e) {
                            failed++;
                        }
                    }

                    currentProgram.endTransaction(txid, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(txid, false);
                    final String msg = "Transaction failed: " + e.getMessage();
                    SwingUtilities.invokeLater(() -> addMessage("system", msg));
                    return;
                }

                // Flush events so decompiler view refreshes
                currentProgram.flushEvents();

                final int ok = applied;
                final int err = failed;
                SwingUtilities.invokeLater(() -> {
                    addMessage("system", "Renamed " + ok + " variable(s)"
                            + (err > 0 ? " (" + err + " failed)" : "") + ".");
                    updateChangeNotification();
                });

            } finally {
                decomp.dispose();
            }
        }, "YAGMCP-DirectiveExecutor").start();
    }

    private boolean isModificationTool(String toolName) {
        return toolName.contains("rename") || toolName.contains("patch") ||
               toolName.contains("comment") || toolName.contains("label");
    }

    private void openSettings() {
        Frame owner = (Frame) SwingUtilities.getWindowAncestor(this);
        SettingsDialog dialog = new SettingsDialog(owner, settings, client);
        dialog.setVisible(true);

        if (dialog.isSaved()) {
            // Update model selector
            modelSelector.setSelectedItem(settings.getModelName());
            addMessage("system", "Settings updated. Server: " + settings.getServerUrl()
                    + ", Model: " + settings.getModelName());
            checkConnection();
        }
    }

    private void checkConnection() {
        statusDot.setForeground(STATUS_CHECKING);
        statusText.setText("Checking...");

        client.testConnection().thenAccept(connected -> {
            SwingUtilities.invokeLater(() -> {
                if (connected) {
                    statusDot.setForeground(STATUS_CONNECTED);
                    statusText.setText("Connected");
                } else {
                    statusDot.setForeground(STATUS_DISCONNECTED);
                    statusText.setText("Disconnected");
                }
            });
        });
    }

    // ========== Message Display ==========

    /**
     * Adds a message to the chat panel and scrolls to the bottom.
     */
    public void addMessage(String role, String text) {
        MessageEntry entry = new MessageEntry(role, text);
        messageHistory.add(entry);

        // Trim history if needed
        while (messageHistory.size() > settings.getMaxHistory()) {
            messageHistory.remove(0);
        }

        JPanel bubble = createMessageBubble(entry);

        SwingUtilities.invokeLater(() -> {
            // Rebuild if we trimmed
            if (messagesPanel.getComponentCount() >= settings.getMaxHistory()) {
                rebuildMessages();
            } else {
                messagesPanel.add(bubble);
                messagesPanel.add(Box.createVerticalStrut(6));
            }
            messagesPanel.revalidate();
            messagesPanel.repaint();
            scrollToBottom();
        });
    }

    private JPanel createMessageBubble(MessageEntry entry) {
        JPanel bubble = new JPanel(new BorderLayout(0, 4));
        Color bg = MessageRenderer.getBackgroundForRole(entry.role);
        bubble.setBackground(bg);
        bubble.setBorder(new CompoundBorder(
                new LineBorder(bg.brighter(), 1, true),
                new EmptyBorder(8, 12, 8, 12)));

        // Role label
        String roleLabel = switch (entry.role.toLowerCase()) {
            case "user" -> "You";
            case "assistant" -> "Assistant";
            case "system" -> "System";
            default -> entry.role;
        };
        JLabel header = new JLabel(roleLabel);
        header.setForeground(MessageRenderer.getForegroundForRole(entry.role).brighter());
        header.setFont(header.getFont().deriveFont(Font.BOLD, 11f));
        bubble.add(header, BorderLayout.NORTH);

        // Message content with markdown
        JTextPane textPane = MessageRenderer.createStyledMessage(entry.text, entry.role);
        textPane.setBackground(bg);
        bubble.add(textPane, BorderLayout.CENTER);

        // Constrain bubble width
        bubble.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        bubble.setAlignmentX(Component.LEFT_ALIGNMENT);

        return bubble;
    }

    private void rebuildMessages() {
        messagesPanel.removeAll();
        for (MessageEntry entry : messageHistory) {
            messagesPanel.add(createMessageBubble(entry));
            messagesPanel.add(Box.createVerticalStrut(6));
        }
    }

    private void clearMessages() {
        messageHistory.clear();
        messagesPanel.removeAll();
        messagesPanel.revalidate();
        messagesPanel.repaint();
    }

    private void scrollToBottom() {
        SwingUtilities.invokeLater(() -> {
            JScrollBar vertical = messagesScroll.getVerticalScrollBar();
            vertical.setValue(vertical.getMaximum());
        });
    }

    private void setSendingState(boolean sending) {
        sendButton.setEnabled(!sending);
        inputField.setEnabled(!sending);
        if (sending) {
            sendButton.setText("\u23F3");  // hourglass
        } else {
            sendButton.setText("\u25B6");  // play triangle
        }
    }

    /**
     * Update context size display based on current context mode and data.
     */
    private void updateContextSizeDisplay(String contextMode) {
        long sizeBytes = contextTracker.getTotalContextSize(contextMode);
        String sizeText;
        Color sizeColor = INPUT_FG;

        if (sizeBytes < 1024) {
            sizeText = "Context: " + sizeBytes + "B";
        } else if (sizeBytes < 1024 * 1024) {
            sizeText = String.format("Context: %.1fKB", sizeBytes / 1024.0);
        } else {
            sizeText = String.format("Context: %.1fMB", sizeBytes / (1024.0 * 1024));
        }

        // Color indicator: green (<100KB), yellow (100-500KB), red (>500KB)
        if (sizeBytes < 100 * 1024) {
            sizeColor = new Color(100, 200, 100);  // Green
        } else if (sizeBytes < 500 * 1024) {
            sizeColor = new Color(200, 200, 100);  // Yellow
        } else {
            sizeColor = new Color(200, 100, 100);  // Red
        }

        if (contextSizeLabel != null) {
            contextSizeLabel.setText(sizeText);
            contextSizeLabel.setForeground(sizeColor);
        }
    }

    /**
     * Updates the connection status indicator (e.g., after settings change).
     */
    public void refreshConnectionStatus() {
        checkConnection();
    }

    // ========== Scrollable panel for word wrap ==========

    /**
     * A JPanel that implements Scrollable so the JScrollPane constrains its width
     * to the viewport. This forces child JTextPanes to wrap text when the window
     * is resized instead of expanding horizontally.
     */
    private static class ScrollablePanel extends JPanel implements Scrollable {
        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 64;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true; // Constrain width to viewport → enables text wrap in child JTextPanes
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    // ========== Inner record for message history ==========

    private static class MessageEntry {
        final String role;
        final String text;

        MessageEntry(String role, String text) {
            this.role = role;
            this.text = text;
        }
    }
}
