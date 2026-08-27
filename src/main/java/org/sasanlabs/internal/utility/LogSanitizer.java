package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled values before writing them to logs. Prevents log forging
 * (CWE-117) by replacing CR, LF, and TAB characters that could allow attackers to inject forged
 * log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes the given value for safe inclusion in log messages by replacing control characters
     * (carriage return, line feed, tab) with underscores.
     *
     * @param value the potentially untrusted value
     * @return sanitized value safe for logging, or "null" if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
