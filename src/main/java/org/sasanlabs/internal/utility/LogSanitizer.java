package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled input before writing it to log messages. Strips CR/LF and
 * other control characters to prevent log forging (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Replaces carriage-return, line-feed, and other ASCII control characters (except tab) with
     * underscore so that attacker-controlled data cannot inject fake log lines.
     *
     * @param input the potentially tainted string
     * @return sanitized string safe for logging, or {@code "null"} if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (Character.isISOControl(c) && c != '\t') {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
