package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize untrusted input before writing it to log messages, preventing log forging
 * (CWE-117) by replacing newline and control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a value for safe inclusion in log output. Replaces carriage-return, line-feed, and
     * other ASCII control characters with an underscore to prevent log injection / forging.
     *
     * @param value the untrusted input (may be {@code null})
     * @return sanitized string safe for logging, or {@code "null"} if input is {@code null}
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "_");
    }
}
