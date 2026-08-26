package org.sasanlabs.internal.utility;

/**
 * Utility class that sanitizes user-controlled values before they are written to log statements.
 * Prevents log forging / log injection (CWE-117) by replacing control characters that could be used
 * to inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and other common control characters with an underscore so
     * that attacker-controlled data cannot forge log entries.
     *
     * @param value the potentially tainted value
     * @return a sanitized string safe for inclusion in log messages, or the literal {@code "null"}
     *     if the input is {@code null}
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "_");
    }
}
