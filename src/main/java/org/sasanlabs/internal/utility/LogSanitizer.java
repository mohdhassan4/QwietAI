package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before it is written to log output, preventing log
 * injection (CWE-117) via CR/LF or other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return, line-feed, and other ASCII control characters from the input so that
     * attacker-controlled data cannot forge additional log entries.
     *
     * @param input the potentially tainted string
     * @return a sanitized copy safe for inclusion in log messages, or {@code "null"} if input is
     *     null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        int len = input.length();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (c < 0x20 && c != '\t') {
                // Replace other control characters (except tab) with underscore
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
