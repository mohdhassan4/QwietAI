package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before it is written to log messages, preventing log
 * forging (CWE-117) via CRLF injection.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Replaces CR, LF, and TAB characters with underscores so that attacker-controlled data cannot
     * forge log entries or corrupt log structure.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\t]", "_");
    }
}
