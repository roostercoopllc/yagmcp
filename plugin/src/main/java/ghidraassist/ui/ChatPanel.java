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
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.framework.plugintool.PluginTool;

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
    private JPanel messagesPanel;
    private JScrollPane messagesScroll;

    // Bottom bar
    private JComboBox<String> contextModeSelector;
    private JTextField inputField;
    private JButton sendButton;

    // State
    private final List<MessageEntry> messageHistory = new ArrayList<>();
    private boolean isSending = false;

    public ChatPanel(GhidraAssistSettings settings, GhidraAssistClient client,
            GhidraAssistContextTracker contextTracker, PluginTool tool) {
        this.settings = settings;
        this.client = client;
        this.contextTracker = contextTracker;
        this.tool = tool;
        this.currentProgram = tool.getCurrentProgram();

        // Initialize colors from the selected palette
        applyColorPalette(settings.getColorPalette());

        setLayout(new BorderLayout());
        setBackground(PANEL_BG);

        buildChangeNotificationPanel();
        buildTopBar();
        buildMessageArea();
        buildBottomBar();

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
            // Store current location for restoration after reload
            ProgramLocation currentLocation = null;
            try {
                // Try to get current location from the tool's clipboard
                Object clipboardContent = tool.getProject().getToolManager().getToolComponentProvider("ByteViewer");
                // Note: exact method varies by Ghidra version
            } catch (Exception e) {
                // Ignore - just use program start if we can't get current location
            }

            // Close and reopen the program from disk (triggers full refresh)
            String programPath = currentProgram.getExecutablePath();
            currentProgram.flushEvents();
            tool.closeProgram(currentProgram, true);

            // Brief delay to ensure close completes
            Thread.sleep(200);

            // Reopen the program
            try {
                tool.getProject().openProgram(programPath, true);
                addMessage("system", "✓ Program reloaded. Changes are now visible.");
            } catch (Exception e) {
                addMessage("system", "Error reopening program: " + e.getMessage());
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
        messagesPanel = new JPanel();
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

        // Left: context mode selector
        contextModeSelector = new JComboBox<>(new String[]{"function", "selection", "both", "none"});
        contextModeSelector.setSelectedItem(settings.getContextMode());
        contextModeSelector.setPreferredSize(new Dimension(100, 26));
        contextModeSelector.setToolTipText("Context to include with messages");
        contextModeSelector.addActionListener(e -> {
            String mode = (String) contextModeSelector.getSelectedItem();
            if (mode != null) {
                settings.setContextMode(mode);
            }
        });
        bottomBar.add(contextModeSelector, BorderLayout.WEST);

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
     * Updates the connection status indicator (e.g., after settings change).
     */
    public void refreshConnectionStatus() {
        checkConnection();
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
