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

    private static final int MAX_LOG_VALUE_LENGTH = 500;

    /**
     * Strips all control characters (ASCII 0x00-0x1F, 0x7F) from the input so that
     * attacker-controlled data cannot forge additional log lines or inject invisible characters.
     * Also truncates to a safe maximum length to prevent log flooding.
     *
     * @param value the potentially tainted value
     * @return sanitized value safe for logging, or "null" literal if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        int len = Math.min(value.length(), MAX_LOG_VALUE_LENGTH);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);
            if (c >= 0x20 && c != 0x7F) {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        return sb.toString();
    }
}
