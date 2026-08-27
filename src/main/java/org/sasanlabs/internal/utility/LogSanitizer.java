package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled input before writing it to logs, preventing log
 * forging (CWE-117) via CRLF injection.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage return, newline, and other control characters from the input so that
     * attacker-controlled data cannot forge log entries.
     *
     * @param input the raw, potentially malicious string
     * @return a sanitized string safe for inclusion in log messages
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\t]", "_");
    }
}
