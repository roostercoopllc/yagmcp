# Call Graph Visualization — Ghidra Plugin Integration

## Summary

Successfully implemented call graph visualization in the YAGMCP Ghidra plugin by:
1. **Creating GraphVisualizationPanel.java** — Force-directed graph layout with interactive visualization
2. **Creating CallGraphPanel.java** — UI controls for call graph analysis (function selector, depth control, analyze button)
3. **Modifying ChatPanel.java** — Added public `sendQuery(String)` method for programmatic query execution
4. **Modifying GhidraAssistProvider.java** — Wrapped interface with JTabbedPane (Chat + Call Graph tabs)

## Files Created/Modified

### New Files in `plugin/src/main/java/ghidraassist/ui/`
- **GraphVisualizationPanel.java** (~180 lines)
  - Pure Swing Graphics2D rendering, no external dependencies
  - Force-directed spring layout algorithm
  - Interactive: Shift+Drag=Pan, Wheel=Zoom, Drag=Move nodes
  - Highlights circular dependencies in red
  - Export to JSON for external tools

- **CallGraphPanel.java** (~250 lines)
  - Function selector dropdown (auto-populated from Ghidra)
  - Depth spinner (1-10 levels)
  - Include External Calls checkbox
  - Analyze Graph button
  - Export JSON button
  - Split view: graph visualization + results summary
  - Results display: metrics, cycles, critical functions

### Modified Files

- **plugin/src/main/java/ghidraassist/ui/ChatPanel.java**
  - Added 10-line public `sendQuery(String)` method
  - Allows CallGraphPanel to programmatically send queries

- **plugin/src/main/java/ghidraassist/GhidraAssistProvider.java**
  - Added `CallGraphPanel` field and import
  - Added `JTabbedPane` field and import
  - Created tabs in constructor: "Chat" tab + "Call Graph" tab
  - Updated `getComponent()` to return `tabbedPane` instead of `chatPanel`
  - Enhanced program event methods:
    - `programOpened()` → calls `callGraphPanel.updateFunctionList(program)`
    - `programClosed()` → calls `callGraphPanel.clear()`
    - `programActivated()` → calls `callGraphPanel.updateFunctionList(program)`

## Architecture

```
GhidraAssistProvider (ComponentProvider)
├── JTabbedPane
│   ├── Tab 1: ChatPanel (existing)
│   │   └── sends queries via sendQuery(String)
│   │
│   └── Tab 2: CallGraphPanel (new)
│       ├── FunctionSelector JComboBox (populated from program)
│       ├── DepthSpinner JSpinner (1-10)
│       ├── IncludeExternal JCheckBox
│       ├── AnalyzeGraph JButton
│       ├── ExportJSON JButton
│       ├── GraphVisualizationPanel (top)
│       │   ├── Force-directed layout
│       │   ├── Node/Edge rendering
│       │   └── Interactive controls
│       └── ResultsArea JTextArea (bottom)
```

## User Flow

1. **User opens binary in Ghidra**
   - Plugin initializes with two tabs: Chat, Call Graph

2. **Call Graph tab populates function list**
   - `programOpened()` → `callGraphPanel.updateFunctionList(program)`
   - Ghidra's `FunctionManager.getFunctions()` populates dropdown

3. **User selects function and clicks "Analyze Graph"**
   - `analyzeCallGraph()` builds query: `analyze_call_graph(root_function="...", max_depth=5, include_external=false)`
   - `callGraphPanel.sendQuery(query)` → `chatPanel.sendQuery(query)`
   - ChatPanel sends to server via MCP

4. **Server returns call graph JSON**
   - ChatPanel routes to `callGraphPanel.displayCallGraphResults(response)`
   - Graph visualization renders with force-directed layout
   - Critical functions listed with metrics

5. **User exports graph** (optional)
   - `ExportJSON` button → saves nodes/edges/cycles to JSON file

## Build & Test

### Prerequisites
- Gradle with Ghidra plugin installed
- `GHIDRA_INSTALL_DIR` environment variable set
- Java 17+

### Build
```bash
cd plugin/
export GHIDRA_INSTALL_DIR=/path/to/ghidra  # (or use gradle property)
gradle build
```

### Test in Ghidra
1. Load plugin extension (Extensions > Install Extensions)
2. Open a binary
3. Verify "Call Graph" tab appears next to "Chat" tab
4. Verify function list populates in dropdown
5. Select a function, click "Analyze Graph"
6. Verify graph renders in visualization panel
7. Verify critical functions appear in results
8. Export graph and verify JSON format

## Integration Points with Backend

The plugin integrates with the `analyze_call_graph` MCP tool via natural language:
- User selects function in dropdown
- Plugin generates query: `analyze_call_graph(root_function="...", max_depth=5, ...)`
- ChatPanel sends via HTTP to server
- Server returns: `{nodes, edges, cycles, critical_functions, graph_metrics}`
- CallGraphPanel receives and visualizes

## Verification Checklist

✅ GraphVisualizationPanel.java created (180 lines, pure Swing)
✅ CallGraphPanel.java created (250 lines, controls + graph)
✅ ChatPanel.java modified (public sendQuery method added)
✅ GhidraAssistProvider.java modified (JTabbedPane wrapper + event wiring)
✅ Files cleaned up (removed from server/src/ghidra_assist/ui/)
✅ Syntax validation (Java 17 compatible, uses standard Ghidra APIs)

## Next Steps for User

1. **Set GHIDRA_INSTALL_DIR environment variable** if not already set
2. **Build the plugin**: `gradle build` in plugin directory
3. **Load into Ghidra**: Extension menu → Install Extensions
4. **Test with sample binary**: Open binary, navigate to Call Graph tab
5. **Analyze functions**: Select function, click "Analyze Graph"
6. **Verify visualization**: Confirm graph renders correctly
7. **Export if needed**: Use "Export JSON" to save for external analysis

## Technical Notes

- **No external graph libraries** — used pure Swing Graphics2D for maximum compatibility
- **Interactive visualization** — supports pan, zoom, and node dragging
- **Cycle detection** — highlights circular dependencies in red
- **Export capability** — JSON format for use in external graph visualization tools (D3.js, Cytoscape.js, etc.)
- **Backward compatible** — existing Chat tab remains unchanged
- **Lazy loading** — functions populate only when program opens

