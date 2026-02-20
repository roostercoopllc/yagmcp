package ghidraassist.ui;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Renders chat message text with basic Markdown formatting into a JTextPane.
 *
 * Supported formatting:
 * - **bold** text
 * - `inline code` in monospace
 * - Fenced code blocks (``` ... ```) with a tinted background
 * - Bullet points (lines starting with - or *)
 * - Headings (lines starting with # / ## / ###)
 */
public class MessageRenderer {

    private static final Color CODE_BG_COLOR = new Color(40, 44, 52);
    private static final Color CODE_FG_COLOR = new Color(171, 178, 191);
    private static final Color USER_BG = new Color(0, 120, 212);
    private static final Color ASSISTANT_BG = new Color(55, 55, 55);
    private static final Color SYSTEM_BG = new Color(80, 60, 20);
    private static final Color USER_FG = Color.WHITE;
    private static final Color ASSISTANT_FG = new Color(220, 220, 220);
    private static final Color SYSTEM_FG = new Color(255, 220, 120);

    private static final Font BASE_FONT = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    private static final Font MONO_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private static final Font BOLD_FONT = BASE_FONT.deriveFont(Font.BOLD);
    private static final Font HEADING_FONT = BASE_FONT.deriveFont(Font.BOLD, 15f);

    private static final Pattern CODE_BLOCK_PATTERN =
            Pattern.compile("```(?:\\w*)\n?(.*?)```", Pattern.DOTALL);
    private static final Pattern INLINE_CODE_PATTERN =
            Pattern.compile("`([^`]+)`");
    private static final Pattern BOLD_PATTERN =
            Pattern.compile("\\*\\*(.+?)\\*\\*");

    private MessageRenderer() {
        // utility class
    }

    /**
     * Returns the background color to use for a message bubble of the given role.
     */
    public static Color getBackgroundForRole(String role) {
        return switch (role.toLowerCase()) {
            case "user", "you" -> USER_BG;
            case "system" -> SYSTEM_BG;
            default -> ASSISTANT_BG;
        };
    }

    /**
     * Returns the foreground color for text of the given role.
     */
    public static Color getForegroundForRole(String role) {
        return switch (role.toLowerCase()) {
            case "user", "you" -> USER_FG;
            case "system" -> SYSTEM_FG;
            default -> ASSISTANT_FG;
        };
    }

    /**
     * Creates a fully styled JTextPane for the given message text and role.
     */
    public static JTextPane createStyledMessage(String text, String role) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.setFont(BASE_FONT);
        pane.setForeground(getForegroundForRole(role));

        StyledDocument doc = pane.getStyledDocument();
        renderMarkdown(doc, text, role);

        return pane;
    }

    /**
     * Renders Markdown-formatted text into a StyledDocument.
     */
    public static void renderMarkdown(StyledDocument doc, String text, String role) {
        Color fg = getForegroundForRole(role);

        // Split on fenced code blocks first
        Matcher codeBlockMatcher = CODE_BLOCK_PATTERN.matcher(text);
        int lastEnd = 0;

        while (codeBlockMatcher.find()) {
            // Render text before the code block
            String before = text.substring(lastEnd, codeBlockMatcher.start());
            renderInlineText(doc, before, fg);

            // Render the code block
            String code = codeBlockMatcher.group(1);
            appendCodeBlock(doc, code);

            lastEnd = codeBlockMatcher.end();
        }

        // Remaining text after last code block
        if (lastEnd < text.length()) {
            renderInlineText(doc, text.substring(lastEnd), fg);
        }
    }

    /**
     * Renders a segment of text that may contain inline formatting (bold, inline code,
     * bullet points, headings) but no fenced code blocks.
     */
    private static void renderInlineText(StyledDocument doc, String text, Color fg) {
        String[] lines = text.split("\n", -1);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            if (i > 0) {
                appendPlain(doc, "\n", fg);
            }

            // Heading detection
            if (line.startsWith("### ")) {
                appendStyled(doc, line.substring(4), fg, BOLD_FONT);
                continue;
            }
            if (line.startsWith("## ")) {
                appendStyled(doc, line.substring(3), fg, HEADING_FONT);
                continue;
            }
            if (line.startsWith("# ")) {
                appendStyled(doc, line.substring(2), fg,
                        BASE_FONT.deriveFont(Font.BOLD, 17f));
                continue;
            }

            // Bullet point detection
            String trimmed = line.stripLeading();
            if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                int indent = line.length() - trimmed.length();
                String bullet = " ".repeat(indent) + "\u2022 " + trimmed.substring(2);
                renderFormattedLine(doc, bullet, fg);
                continue;
            }

            renderFormattedLine(doc, line, fg);
        }
    }

    /**
     * Renders a single line that may contain **bold** and `inline code`.
     */
    private static void renderFormattedLine(StyledDocument doc, String line, Color fg) {
        // Process inline patterns: bold and inline code
        // Strategy: find the earliest match of either pattern, render text before it,
        // render the match with styling, then repeat.

        int pos = 0;
        while (pos < line.length()) {
            Matcher boldMatcher = BOLD_PATTERN.matcher(line);
            Matcher codeMatcher = INLINE_CODE_PATTERN.matcher(line);

            boolean foundBold = boldMatcher.find(pos);
            boolean foundCode = codeMatcher.find(pos);

            if (!foundBold && !foundCode) {
                // No more patterns; emit remainder as plain text
                appendPlain(doc, line.substring(pos), fg);
                break;
            }

            int boldStart = foundBold ? boldMatcher.start() : Integer.MAX_VALUE;
            int codeStart = foundCode ? codeMatcher.start() : Integer.MAX_VALUE;

            if (boldStart <= codeStart && foundBold) {
                // Emit text before bold
                if (boldMatcher.start() > pos) {
                    appendPlain(doc, line.substring(pos, boldMatcher.start()), fg);
                }
                appendStyled(doc, boldMatcher.group(1), fg, BOLD_FONT);
                pos = boldMatcher.end();
            } else if (foundCode) {
                // Emit text before inline code
                if (codeMatcher.start() > pos) {
                    appendPlain(doc, line.substring(pos, codeMatcher.start()), fg);
                }
                appendInlineCode(doc, codeMatcher.group(1));
                pos = codeMatcher.end();
            }
        }
    }

    // --- Low-level append helpers ---

    private static void appendPlain(StyledDocument doc, String text, Color fg) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, BASE_FONT.getFamily());
        StyleConstants.setFontSize(attrs, BASE_FONT.getSize());
        StyleConstants.setForeground(attrs, fg);
        insertText(doc, text, attrs);
    }

    private static void appendStyled(StyledDocument doc, String text, Color fg, Font font) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, font.getFamily());
        StyleConstants.setFontSize(attrs, font.getSize());
        StyleConstants.setBold(attrs, font.isBold());
        StyleConstants.setItalic(attrs, font.isItalic());
        StyleConstants.setForeground(attrs, fg);
        insertText(doc, text, attrs);
    }

    private static void appendInlineCode(StyledDocument doc, String code) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, MONO_FONT.getFamily());
        StyleConstants.setFontSize(attrs, MONO_FONT.getSize());
        StyleConstants.setForeground(attrs, CODE_FG_COLOR);
        StyleConstants.setBackground(attrs, CODE_BG_COLOR);
        insertText(doc, code, attrs);
    }

    private static void appendCodeBlock(StyledDocument doc, String code) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(attrs, MONO_FONT.getFamily());
        StyleConstants.setFontSize(attrs, MONO_FONT.getSize());
        StyleConstants.setForeground(attrs, CODE_FG_COLOR);
        StyleConstants.setBackground(attrs, CODE_BG_COLOR);

        insertText(doc, "\n", attrs);
        insertText(doc, code, attrs);
        if (!code.endsWith("\n")) {
            insertText(doc, "\n", attrs);
        }
    }

    private static void insertText(StyledDocument doc, String text, AttributeSet attrs) {
        try {
            doc.insertString(doc.getLength(), text, attrs);
        } catch (BadLocationException e) {
            // Should not happen when inserting at end
            throw new RuntimeException("Failed to insert styled text", e);
        }
    }
}
