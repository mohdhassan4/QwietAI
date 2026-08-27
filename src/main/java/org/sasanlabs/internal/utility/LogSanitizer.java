package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to logs, preventing log forging
 * (CWE-117). Strips carriage return, newline, and tab characters that could be used to inject
 * forged log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a value for safe inclusion in log messages by replacing CR, LF, and TAB characters
     * with underscores.
     *
     * @param value the potentially tainted value
     * @return sanitized value safe for logging, or "null" if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
