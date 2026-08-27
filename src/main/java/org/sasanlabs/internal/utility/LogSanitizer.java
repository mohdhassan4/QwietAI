package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing untrusted input before writing it to log files, preventing log
 * forging/injection attacks by stripping CR, LF, and other non-printable control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes the given input for safe inclusion in log messages. Replaces carriage return, line
     * feed, and other ASCII control characters (except tab) with an underscore to prevent log
     * injection.
     *
     * @param input the untrusted input string
     * @return a sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (c < 0x20 && c != '\t') {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
