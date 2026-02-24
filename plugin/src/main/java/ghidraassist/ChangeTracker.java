package ghidraassist;

import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Tracks changes made to Ghidra programs via modification tools.
 *
 * Maintains a list of modifications with timestamps and allows
 * the UI to notify users when the program has been modified
 * and needs to be reloaded.
 */
public class ChangeTracker {
    public static class Change {
        public enum Type {
            RENAME_FUNCTION("Function renamed"),
            RENAME_VARIABLE("Variable renamed"),
            SET_COMMENT("Comment added"),
            PATCH_BYTES("Bytes patched"),
            RENAME_LABEL("Label renamed");

            public final String description;
            Type(String description) {
                this.description = description;
            }
        }

        public final Type type;
        public final String toolName;
        public final String details;
        public final LocalDateTime timestamp;
        public final String address;

        public Change(Type type, String toolName, String details, String address) {
            this.type = type;
            this.toolName = toolName;
            this.details = details;
            this.address = address;
            this.timestamp = LocalDateTime.now();
        }

        @Override
        public String toString() {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
            return String.format("[%s] %s: %s%s",
                timestamp.format(formatter),
                type.description,
                details,
                address != null ? " @ " + address : ""
            );
        }
    }

    private final List<Change> changes = Collections.synchronizedList(new ArrayList<>());
    private static final int MAX_CHANGES = 50;  // Keep last 50 changes

    /**
     * Record a modification made to the program.
     */
    public void recordChange(Change.Type type, String toolName, String details, String address) {
        changes.add(new Change(type, toolName, details, address));

        // Keep list size bounded
        if (changes.size() > MAX_CHANGES) {
            changes.remove(0);
        }
    }

    /**
     * Check if there are pending changes that need to be reloaded.
     */
    public boolean hasChanges() {
        return !changes.isEmpty();
    }

    /**
     * Get all pending changes.
     */
    public List<Change> getChanges() {
        return new ArrayList<>(changes);
    }

    /**
     * Get a human-readable summary of changes.
     */
    public String getSummary() {
        if (changes.isEmpty()) {
            return "No pending changes.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Program has been modified:\n\n");

        for (Change change : changes) {
            sb.append("• ").append(change.toString()).append("\n");
        }

        sb.append("\nReload the program to see changes.");
        return sb.toString();
    }

    /**
     * Clear all recorded changes (called after reload).
     */
    public void clearChanges() {
        changes.clear();
    }

    /**
     * Extract change information from tool response.
     */
    public void trackToolResponse(String toolName, java.util.Map<String, ?> response) {
        if (response == null || response.get("success") == Boolean.FALSE) {
            return;  // Don't track failed operations
        }

        switch (toolName) {
            case "rename_function":
                recordChange(
                    Change.Type.RENAME_FUNCTION,
                    toolName,
                    String.format("%s → %s",
                        response.get("old_name"),
                        response.get("new_name")),
                    (String) response.get("address")
                );
                break;

            case "rename_variable":
                recordChange(
                    Change.Type.RENAME_VARIABLE,
                    toolName,
                    String.format("%s → %s in %s",
                        response.get("old_name"),
                        response.get("new_name"),
                        response.get("function")),
                    null
                );
                break;

            case "set_comment":
                recordChange(
                    Change.Type.SET_COMMENT,
                    toolName,
                    String.format("%s comment: %s",
                        response.get("comment_type"),
                        response.get("new_comment")),
                    (String) response.get("address")
                );
                break;

            case "patch_bytes":
                recordChange(
                    Change.Type.PATCH_BYTES,
                    toolName,
                    String.format("%s bytes: %s → %s",
                        response.get("length"),
                        response.get("old_bytes"),
                        response.get("new_bytes")),
                    (String) response.get("address")
                );
                break;

            case "rename_label":
                recordChange(
                    Change.Type.RENAME_LABEL,
                    toolName,
                    String.format("%s → %s",
                        response.get("old_name"),
                        response.get("new_name")),
                    (String) response.get("address")
                );
                break;
        }
    }
}
