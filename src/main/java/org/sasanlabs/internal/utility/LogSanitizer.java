package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing it to logs, preventing log
 * injection/forging (CWE-117). Replaces CR, LF, TAB, and other control characters with
 * underscores.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Strips control characters (\\r, \\n, \\t, and other C0/C1 controls) from the input string,
     * replacing them with underscores. Returns {@code "null"} for null input so logging remains
     * safe.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "_");
    }
}
