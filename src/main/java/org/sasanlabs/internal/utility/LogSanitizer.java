package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled input before writing to logs, preventing log forging
 * (CWE-117) via CRLF injection.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return and newline characters from the input so that attacker-controlled data
     * cannot forge additional log lines.
     *
     * @param value the potentially tainted string
     * @return sanitized string safe for inclusion in log messages, or {@code "null"} if value is
     *     null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n]", "");
    }
}
