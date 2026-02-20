package ghidraassist.ui;

import ghidraassist.GhidraAssistClient;
import ghidraassist.GhidraAssistSettings;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * Quick-settings dialog accessible from the chat panel's gear icon.
 * Allows editing server URL, model name, and testing the connection.
 */
public class SettingsDialog extends JDialog {

    private final GhidraAssistSettings settings;
    private final GhidraAssistClient client;

    private JTextField serverUrlField;
    private JTextField modelField;
    private JLabel statusLabel;
    private JButton testButton;
    private JButton saveButton;
    private JButton cancelButton;

    private boolean saved = false;

    public SettingsDialog(Frame owner, GhidraAssistSettings settings, GhidraAssistClient client) {
        super(owner, "YAGMCP Settings", true);
        this.settings = settings;
        this.client = client;
        buildUI();
        pack();
        setMinimumSize(new Dimension(450, 250));
        setLocationRelativeTo(owner);
    }

    private void buildUI() {
        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(new EmptyBorder(15, 15, 15, 15));

        // --- Form panel ---
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints labelGbc = new GridBagConstraints();
        labelGbc.anchor = GridBagConstraints.WEST;
        labelGbc.insets = new Insets(4, 4, 4, 8);
        labelGbc.gridx = 0;

        GridBagConstraints fieldGbc = new GridBagConstraints();
        fieldGbc.fill = GridBagConstraints.HORIZONTAL;
        fieldGbc.weightx = 1.0;
        fieldGbc.insets = new Insets(4, 0, 4, 4);
        fieldGbc.gridx = 1;

        // Server URL
        labelGbc.gridy = 0;
        form.add(new JLabel("Server URL:"), labelGbc);
        serverUrlField = new JTextField(settings.getServerUrl(), 30);
        fieldGbc.gridy = 0;
        form.add(serverUrlField, fieldGbc);

        // Model
        labelGbc.gridy = 1;
        form.add(new JLabel("Model:"), labelGbc);
        modelField = new JTextField(settings.getModelName(), 30);
        fieldGbc.gridy = 1;
        form.add(modelField, fieldGbc);

        // Test connection row
        labelGbc.gridy = 2;
        form.add(new JLabel(""), labelGbc);

        JPanel testPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        testButton = new JButton("Test Connection");
        statusLabel = new JLabel(" ");
        statusLabel.setBorder(new EmptyBorder(0, 10, 0, 0));
        testPanel.add(testButton);
        testPanel.add(statusLabel);
        fieldGbc.gridy = 2;
        form.add(testPanel, fieldGbc);

        content.add(form, BorderLayout.CENTER);

        // --- Button bar ---
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        saveButton = new JButton("Save");
        cancelButton = new JButton("Cancel");
        buttons.add(saveButton);
        buttons.add(cancelButton);
        content.add(buttons, BorderLayout.SOUTH);

        setContentPane(content);

        // --- Actions ---

        testButton.addActionListener(e -> testConnection());
        saveButton.addActionListener(e -> save());
        cancelButton.addActionListener(e -> dispose());

        getRootPane().setDefaultButton(saveButton);

        // Escape key closes dialog
        getRootPane().registerKeyboardAction(e -> dispose(),
                KeyStroke.getKeyStroke("ESCAPE"),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    private void testConnection() {
        String url = serverUrlField.getText().trim();
        if (url.isEmpty()) {
            statusLabel.setText("URL cannot be empty");
            statusLabel.setForeground(Color.RED);
            return;
        }

        testButton.setEnabled(false);
        statusLabel.setText("Testing...");
        statusLabel.setForeground(Color.YELLOW);

        // Create a temporary client with the entered URL to test
        GhidraAssistClient testClient = new GhidraAssistClient(url, modelField.getText().trim());
        testClient.testConnection().thenAccept(success -> {
            SwingUtilities.invokeLater(() -> {
                testButton.setEnabled(true);
                if (success) {
                    statusLabel.setText("Connected");
                    statusLabel.setForeground(new Color(0, 200, 0));
                } else {
                    statusLabel.setText("Connection failed");
                    statusLabel.setForeground(Color.RED);
                }
            });
        });
    }

    private void save() {
        String url = serverUrlField.getText().trim();
        String model = modelField.getText().trim();

        if (url.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Server URL cannot be empty.",
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (model.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Model name cannot be empty.",
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        settings.setServerUrl(url);
        settings.setModelName(model);

        // Also update the live client
        client.setServerUrl(url);
        client.setModel(model);

        saved = true;
        dispose();
    }

    /**
     * Returns true if the user clicked Save (as opposed to Cancel / Escape).
     */
    public boolean isSaved() {
        return saved;
    }
}
