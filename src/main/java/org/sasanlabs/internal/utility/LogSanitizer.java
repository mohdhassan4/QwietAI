package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before it is written to log statements. Strips
 * newline and tab characters that could be used for log injection/forging attacks.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Sanitizes the given value by replacing CR, LF, and TAB characters with underscores. Returns
     * an empty string if the input is null.
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
