package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before writing it to log statements. Prevents log
 * forging (CWE-117) by replacing newline and carriage-return characters that could allow an
 * attacker to inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Strips characters that can forge log entries ({@code \r}, {@code \n}, {@code \t}) from the
     * given input, replacing them with underscores. Returns {@code "null"} for null input so
     * callers do not need a null-check.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\t]", "_");
    }
}
