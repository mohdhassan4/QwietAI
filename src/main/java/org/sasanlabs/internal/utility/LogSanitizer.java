package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing it to log messages. Prevents log forging
 * by replacing newline and carriage-return characters with their escaped representations, so
 * attackers cannot inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes the given value for safe inclusion in log output. Replaces CR, LF, and tab
     * characters with visible escape sequences and strips other ASCII control characters.
     *
     * @param value the potentially attacker-controlled string
     * @return a sanitized string safe for logging, or the literal {@code "null"} if input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\t') {
                sb.append("\\t");
            } else if (Character.isISOControl(c)) {
                // Strip other control characters entirely
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
