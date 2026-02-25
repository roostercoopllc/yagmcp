package ghidraassist.ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.*;
import java.util.List;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

/**
 * Call Graph Analysis Panel for YAGMCP Ghidra plugin.
 * Provides UI controls for analyzing function call dependencies and visualizing the call graph.
 */
public class CallGraphPanel extends JPanel {
    private JComboBox<String> functionSelector;
    private JSpinner depthSpinner;
    private JCheckBox includeExternalCheckBox;
    private JButton analyzeButton;
    private JButton exportButton;
    private JTextArea resultsArea;
    private GraphVisualizationPanel graphPanel;
    private ChatPanel chatPanel;
    private Program currentProgram;
    private List<String> allFunctionNames = new ArrayList<>();  // Full list of functions for filtering

    public CallGraphPanel(ChatPanel chatPanel) {
        this.chatPanel = chatPanel;
        this.currentProgram = null;
        initComponents();
        setupKeyboardShortcuts();
    }

    private void initComponents() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            "Call Graph Analysis",
            TitledBorder.LEFT,
            TitledBorder.TOP
        ));

        // Control panel
        JPanel controlPanel = createControlPanel();
        add(controlPanel, BorderLayout.NORTH);

        // Splitter with graph and results
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.6);

        // Graph visualization area
        graphPanel = new GraphVisualizationPanel();
        JPanel graphWrapper = new JPanel(new BorderLayout());
        graphWrapper.setBorder(new TitledBorder("Graph Visualization"));
        graphWrapper.add(graphPanel, BorderLayout.CENTER);
        splitPane.setTopComponent(graphWrapper);

        // Results area
        resultsArea = new JTextArea();
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        resultsArea.setLineWrap(true);
        JScrollPane scrollPane = new JScrollPane(resultsArea);
        scrollPane.setBorder(new TitledBorder("Analysis Results"));
        splitPane.setBottomComponent(scrollPane);

        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * Set up keyboard shortcuts for Call Graph Panel.
     * Ctrl+L: Refresh function list
     * Ctrl+E: Export as JSON
     */
    private void setupKeyboardShortcuts() {
        addKeyListener(new KeyListener() {
            @Override
            public void keyPressed(KeyEvent e) {
                // Ctrl+L: Refresh function list
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_L) {
                    if (currentProgram != null) {
                        updateFunctionList(currentProgram);
                    }
                    e.consume();
                }
                // Ctrl+E: Export graph as JSON
                else if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_E) {
                    exportGraph();
                    e.consume();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {}

            @Override
            public void keyTyped(KeyEvent e) {}
        });
        setFocusable(true);
    }

    private JPanel createControlPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Function selector with filtering
        panel.add(new JLabel("Root Function:"));
        functionSelector = new JComboBox<>();
        functionSelector.setPreferredSize(new Dimension(250, 25));
        functionSelector.setEditable(true);
        functionSelector.addActionListener(e -> updateDepthSpinner());

        // Add filtering on text input
        JTextField editor = (JTextField) functionSelector.getEditor().getEditorComponent();
        editor.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateFunctionFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateFunctionFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateFunctionFilter(); }
        });

        panel.add(functionSelector);

        // Depth spinner
        panel.add(new JLabel("Max Depth:"));
        depthSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 10, 1));
        depthSpinner.setPreferredSize(new Dimension(60, 25));
        panel.add(depthSpinner);

        // Include external checkbox
        includeExternalCheckBox = new JCheckBox("Include External Calls", false);
        panel.add(includeExternalCheckBox);

        // Analyze button
        analyzeButton = new JButton("Analyze Graph");
        analyzeButton.addActionListener(e -> analyzeCallGraph());
        panel.add(analyzeButton);

        // Export button
        exportButton = new JButton("Export as JSON");
        exportButton.addActionListener(e -> exportGraph());
        exportButton.setEnabled(false);
        panel.add(exportButton);

        return panel;
    }

    private void updateDepthSpinner() {
        // Could adjust depth based on function selection
        // (e.g., library functions use lower depth)
    }

    private void analyzeCallGraph() {
        String function = (String) functionSelector.getSelectedItem();
        if (function == null || function.isEmpty()) {
            resultsArea.setText("Error: Please select a function first.");
            return;
        }

        int depth = (Integer) depthSpinner.getValue();
        boolean includeExternal = includeExternalCheckBox.isSelected();

        // Disable controls during analysis
        analyzeButton.setEnabled(false);
        resultsArea.setText("Analyzing call graph...");

        // Build query for chat
        String query = String.format(
            "analyze_call_graph(root_function=\"%s\", max_depth=%d, include_external=%s)",
            escapeString(function), depth, includeExternal
        );

        // Send to chat for processing
        chatPanel.sendQuery(query);

        // Re-enable after a delay (chat will process the result)
        javax.swing.Timer timer = new javax.swing.Timer(1000, e -> analyzeButton.setEnabled(true));
        timer.setRepeats(false);
        timer.start();
    }

    private void exportGraph() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Call Graph");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setSelectedFile(new java.io.File("callgraph.json"));

        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                graphPanel.exportToJSON(file);
                JOptionPane.showMessageDialog(
                    this,
                    "Graph exported to: " + file.getAbsolutePath(),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE
                );
            } catch (Exception e) {
                JOptionPane.showMessageDialog(
                    this,
                    "Error exporting graph: " + e.getMessage(),
                    "Export Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    public void displayCallGraphResults(Map<String, Object> response) {
        if (response == null) {
            resultsArea.setText("Error: No response from server");
            return;
        }

        if (!(boolean) response.getOrDefault("success", false)) {
            resultsArea.setText("Error: " + response.getOrDefault("error", "Unknown error"));
            return;
        }

        try {
            // Extract graph data
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> nodes = (List<Map<String, Object>>) response.get("nodes");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> edges = (List<Map<String, Object>>) response.get("edges");
            @SuppressWarnings("unchecked")
            List<List<String>> cycles = (List<List<String>>) response.get("cycles");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> criticalFuncs = (List<Map<String, Object>>) response.get("critical_functions");
            @SuppressWarnings("unchecked")
            Map<String, Object> metrics = (Map<String, Object>) response.get("graph_metrics");

            // Display in graph panel
            graphPanel.displayGraph(nodes, edges, cycles);
            exportButton.setEnabled(true);

            // Display results summary
            StringBuilder results = new StringBuilder();
            results.append("=== Call Graph Analysis Results ===\n\n");

            String rootFunc = (String) response.get("root_function");
            if (!"all".equals(rootFunc)) {
                results.append(String.format("Root Function: %s\n", rootFunc));
            }
            results.append(String.format("Functions Analyzed: %d\n", nodes.size()));
            results.append(String.format("Function Calls: %d\n", edges.size()));

            if (metrics != null) {
                results.append(String.format("Average Out-Degree: %.2f\n",
                    ((Number) metrics.getOrDefault("avg_out_degree", 0)).doubleValue()));
                results.append(String.format("Max Out-Degree: %d\n",
                    ((Number) metrics.getOrDefault("max_out_degree", 0)).intValue()));
                results.append(String.format("Cyclomatic Complexity: %.2f\n\n",
                    ((Number) metrics.getOrDefault("cyclomatic_complexity", 0)).doubleValue()));
            }

            if (cycles != null && !cycles.isEmpty()) {
                results.append(String.format("Circular Dependencies Found: %d\n", cycles.size()));
                results.append("─".repeat(50)).append("\n");
                for (int i = 0; i < Math.min(cycles.size(), 5); i++) {
                    List<String> cycle = cycles.get(i);
                    results.append("  ").append(String.join(" → ", cycle));
                    if (i < cycles.size() - 1) {
                        results.append("\n");
                    }
                }
                results.append("\n\n");
            }

            if (criticalFuncs != null && !criticalFuncs.isEmpty()) {
                results.append("Top Critical Functions:\n");
                results.append("─".repeat(50)).append("\n");
                for (int i = 0; i < Math.min(criticalFuncs.size(), 5); i++) {
                    Map<String, Object> func = criticalFuncs.get(i);
                    results.append(String.format(
                        "%d. %s (importance: %.2f)\n   in: %d, out: %d, role: %s\n",
                        i + 1,
                        func.get("name"),
                        ((Number) func.get("importance_score")).doubleValue(),
                        ((Number) func.get("in_degree")).intValue(),
                        ((Number) func.get("out_degree")).intValue(),
                        func.get("role")
                    ));
                }
            }

            String analysisNote = (String) response.get("analysis_note");
            if (analysisNote != null) {
                results.append("\n").append(analysisNote);
            }

            resultsArea.setText(results.toString());
            resultsArea.setCaretPosition(0);

        } catch (Exception e) {
            resultsArea.setText("Error processing response: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void updateFunctionList(Program program) {
        this.currentProgram = program;
        allFunctionNames.clear();
        functionSelector.removeAllItems();

        if (program == null) {
            return;
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();
            for (Function func : functionManager.getFunctions(true)) {
                allFunctionNames.add(func.getName());
                functionSelector.addItem(func.getName());
            }
            if (functionSelector.getItemCount() > 0) {
                functionSelector.setSelectedIndex(0);
            }
        } catch (Exception e) {
            resultsArea.setText("Error loading functions: " + e.getMessage());
        }
    }

    public void clear() {
        this.currentProgram = null;
        allFunctionNames.clear();
        functionSelector.removeAllItems();
        resultsArea.setText("");
        graphPanel.clear();
        exportButton.setEnabled(false);
    }

    /**
     * Filter function list based on search text (fuzzy matching).
     * Called when user types in the function selector.
     */
    private void updateFunctionFilter() {
        JTextField editor = (JTextField) functionSelector.getEditor().getEditorComponent();
        String searchText = editor.getText().toLowerCase();

        functionSelector.removeAllItems();

        if (searchText.isEmpty()) {
            // Show all functions
            for (String func : allFunctionNames) {
                functionSelector.addItem(func);
            }
        } else {
            // Filter by fuzzy match: functions containing all search terms
            String[] searchTerms = searchText.split("\\s+");
            int matchCount = 0;
            for (String func : allFunctionNames) {
                String funcLower = func.toLowerCase();
                boolean matches = true;
                for (String term : searchTerms) {
                    if (!funcLower.contains(term)) {
                        matches = false;
                        break;
                    }
                }
                if (matches) {
                    functionSelector.addItem(func);
                    matchCount++;
                }
            }

            // Show match count in editor if no text box available
            if (matchCount == 0) {
                // Keep editor text even if no matches
            }
        }

        // Keep showing the dropdown
        if (functionSelector.getItemCount() > 0) {
            functionSelector.showPopup();
        }
    }

    private String escapeString(String str) {
        return str.replace("\"", "\\\"");
    }
}
