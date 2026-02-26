package ghidraassist;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import java.awt.Color;

/**
 * Manages persistent settings for the GhidraAssist plugin.
 * Settings are stored in Ghidra's tool options under the "YAGMCP" category.
 */
public class GhidraAssistSettings implements OptionsChangeListener {

    /**
     * Predefined color palettes for the chat window UI.
     */
    public enum ColorPalette {
        DARK("Dark (Default)",
             new Color(30, 30, 30),      // Panel BG
             new Color(45, 45, 45),      // Input BG
             new Color(220, 220, 220),   // Input FG
             new Color(38, 38, 38)),     // Bar BG

        LIGHT("Light",
              new Color(245, 245, 245),  // Panel BG
              new Color(255, 255, 255),  // Input BG
              new Color(30, 30, 30),     // Input FG
              new Color(235, 235, 235)), // Bar BG

        MONOKAI("Monokai",
                new Color(39, 40, 34),   // Panel BG (darker)
                new Color(49, 50, 44),   // Input BG
                new Color(248, 248, 242), // Input FG
                new Color(59, 60, 54)),  // Bar BG

        NORD("Nord",
             new Color(46, 52, 64),      // Panel BG
             new Color(59, 66, 82),      // Input BG
             new Color(236, 239, 244),   // Input FG
             new Color(46, 52, 64));     // Bar BG

        public final String displayName;
        public final Color panelBg;
        public final Color inputBg;
        public final Color inputFg;
        public final Color barBg;

        ColorPalette(String displayName, Color panelBg, Color inputBg, Color inputFg, Color barBg) {
            this.displayName = displayName;
            this.panelBg = panelBg;
            this.inputBg = inputBg;
            this.inputFg = inputFg;
            this.barBg = barBg;
        }

        public static ColorPalette fromName(String name) {
            try {
                return ColorPalette.valueOf(name);
            } catch (IllegalArgumentException e) {
                return DARK;  // Default fallback
            }
        }
    }

    public static final String OPTIONS_CATEGORY = "YAGMCP";

    private static final String OPT_SERVER_URL = "Server URL";
    private static final String OPT_MODEL_NAME = "Model Name";
    private static final String OPT_AUTO_CONTEXT = "Auto-Include Context";
    private static final String OPT_CONTEXT_MODE = "Context Mode";
    private static final String OPT_MAX_HISTORY = "Max History";
    private static final String OPT_AUTO_RELOAD = "Auto-Reload on Changes";
    private static final String OPT_COLOR_PALETTE = "Color Palette";
    private static final String OPT_REQUEST_TIMEOUT = "Request Timeout (seconds)";

    private static final String DEFAULT_SERVER_URL = "http://localhost:8889";
    private static final String DEFAULT_MODEL_NAME = "qwen2.5-coder:7b";
    private static final boolean DEFAULT_AUTO_CONTEXT = true;
    private static final String DEFAULT_CONTEXT_MODE = "function";
    private static final int DEFAULT_MAX_HISTORY = 50;
    private static final boolean DEFAULT_AUTO_RELOAD = true;
    private static final String DEFAULT_COLOR_PALETTE = "DARK";
    private static final int DEFAULT_REQUEST_TIMEOUT = 300;

    private String serverUrl;
    private String modelName;
    private boolean autoIncludeContext;
    private String contextMode;
    private int maxHistory;
    private boolean autoReload;
    private ColorPalette colorPalette;
    private int requestTimeout;

    private final ToolOptions options;
    private SettingsChangeCallback changeCallback;

    /**
     * Callback interface notified when any setting changes.
     */
    @FunctionalInterface
    public interface SettingsChangeCallback {
        void onSettingsChanged(GhidraAssistSettings settings);
    }

    public GhidraAssistSettings(PluginTool tool) {
        options = tool.getOptions(OPTIONS_CATEGORY);
        registerDefaults();
        loadAll();
        options.addOptionsChangeListener(this);
    }

    private void registerDefaults() {
        options.registerOption(OPT_SERVER_URL, DEFAULT_SERVER_URL, null,
                "URL of the YAGMCP server (e.g. http://host:8889)");
        options.registerOption(OPT_MODEL_NAME, DEFAULT_MODEL_NAME, null,
                "LLM model identifier to use for chat");
        options.registerOption(OPT_AUTO_CONTEXT, DEFAULT_AUTO_CONTEXT, null,
                "Automatically include Ghidra context (function, address) with chat messages");
        options.registerOption(OPT_CONTEXT_MODE, DEFAULT_CONTEXT_MODE, null,
                "Context mode: function, selection, or both");
        options.registerOption(OPT_MAX_HISTORY, DEFAULT_MAX_HISTORY, null,
                "Maximum number of messages to keep in conversation history");
        options.registerOption(OPT_AUTO_RELOAD, DEFAULT_AUTO_RELOAD, null,
                "Automatically reload program when MCP tools make changes (hot-reload)");
        options.registerOption(OPT_COLOR_PALETTE, DEFAULT_COLOR_PALETTE, null,
                "Chat window color palette: DARK, LIGHT, MONOKAI, or NORD");
        options.registerOption(OPT_REQUEST_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, null,
                "HTTP request timeout in seconds for chat requests (increase for slow LLMs)");
    }

    private void loadAll() {
        serverUrl = options.getString(OPT_SERVER_URL, DEFAULT_SERVER_URL);
        modelName = options.getString(OPT_MODEL_NAME, DEFAULT_MODEL_NAME);
        autoIncludeContext = options.getBoolean(OPT_AUTO_CONTEXT, DEFAULT_AUTO_CONTEXT);
        contextMode = options.getString(OPT_CONTEXT_MODE, DEFAULT_CONTEXT_MODE);
        maxHistory = options.getInt(OPT_MAX_HISTORY, DEFAULT_MAX_HISTORY);
        autoReload = options.getBoolean(OPT_AUTO_RELOAD, DEFAULT_AUTO_RELOAD);
        String paletteName = options.getString(OPT_COLOR_PALETTE, DEFAULT_COLOR_PALETTE);
        colorPalette = ColorPalette.fromName(paletteName);
        requestTimeout = options.getInt(OPT_REQUEST_TIMEOUT, DEFAULT_REQUEST_TIMEOUT);
    }

    @Override
    public void optionsChanged(ToolOptions toolOptions, String optionName, Object oldValue,
            Object newValue) {
        loadAll();
        if (changeCallback != null) {
            changeCallback.onSettingsChanged(this);
        }
    }

    // --- Accessors ---

    public String getServerUrl() {
        return serverUrl;
    }

    public String getModelName() {
        return modelName;
    }

    public boolean isAutoIncludeContext() {
        return autoIncludeContext;
    }

    public String getContextMode() {
        return contextMode;
    }

    public int getMaxHistory() {
        return maxHistory;
    }

    public boolean isAutoReload() {
        return autoReload;
    }

    public ColorPalette getColorPalette() {
        return colorPalette;
    }

    public int getRequestTimeout() {
        return requestTimeout;
    }

    // --- Mutators (also persist to tool options) ---

    public void setServerUrl(String url) {
        this.serverUrl = url;
        options.setString(OPT_SERVER_URL, url);
    }

    public void setModelName(String model) {
        this.modelName = model;
        options.setString(OPT_MODEL_NAME, model);
    }

    public void setAutoIncludeContext(boolean auto) {
        this.autoIncludeContext = auto;
        options.setBoolean(OPT_AUTO_CONTEXT, auto);
    }

    public void setContextMode(String mode) {
        this.contextMode = mode;
        options.setString(OPT_CONTEXT_MODE, mode);
    }

    public void setMaxHistory(int max) {
        this.maxHistory = max;
        options.setInt(OPT_MAX_HISTORY, max);
    }

    public void setAutoReload(boolean autoReload) {
        this.autoReload = autoReload;
        options.setBoolean(OPT_AUTO_RELOAD, autoReload);
    }

    public void setColorPalette(ColorPalette palette) {
        this.colorPalette = palette;
        options.setString(OPT_COLOR_PALETTE, palette.name());
    }

    public void setRequestTimeout(int seconds) {
        this.requestTimeout = seconds;
        options.setInt(OPT_REQUEST_TIMEOUT, seconds);
    }

    public void setChangeCallback(SettingsChangeCallback callback) {
        this.changeCallback = callback;
    }

    public void dispose() {
        options.removeOptionsChangeListener(this);
    }
}
