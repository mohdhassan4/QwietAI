package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before it is written to logs, preventing log forging
 * (CWE-117). Replaces CR, LF, and other control characters with underscores.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a string for safe inclusion in log messages by replacing carriage return, line feed,
     * and other control characters (except tab) with an underscore.
     *
     * @param input the potentially tainted input
     * @return sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n' || (Character.isISOControl(c) && c != '\t')) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
