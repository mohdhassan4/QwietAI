package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before logging, preventing log forging (CWE-117).
 * Strips CR, LF, and other control characters that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage return, line feed, and other control characters with underscores so that
     * attacker-controlled input cannot forge log entries.
     *
     * @param value the untrusted value to sanitize
     * @return sanitized string safe for inclusion in log messages, or "null" if input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "_");
    }
}
