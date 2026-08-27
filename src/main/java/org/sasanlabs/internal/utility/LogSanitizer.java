package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled values before passing them to log statements, preventing log
 * forging / log injection attacks where an attacker can inject fake log entries via newline or other
 * control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Replaces carriage-return, line-feed, and tab characters with underscores so that
     * attacker-controlled data cannot forge additional log lines.
     *
     * @param value the potentially tainted value
     * @return sanitized value safe for logging, or "null" literal if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
