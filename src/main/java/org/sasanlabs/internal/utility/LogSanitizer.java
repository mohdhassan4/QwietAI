package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize untrusted input before including it in log messages, preventing log
 * forging/injection (CWE-117). Strips CR, LF, and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and other ISO control characters with underscore so that
     * attacker-controlled data cannot inject fake log entries.
     *
     * @param input the untrusted value to sanitize; may be {@code null}
     * @return sanitized string safe for log output, or {@code "null"} if input is {@code null}
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        int len = input.length();
        StringBuilder sb = null;
        for (int i = 0; i < len; i++) {
            char ch = input.charAt(i);
            if (ch == '\r' || ch == '\n' || (Character.isISOControl(ch) && ch != '\t')) {
                if (sb == null) {
                    sb = new StringBuilder(len);
                    sb.append(input, 0, i);
                }
                sb.append('_');
            } else if (sb != null) {
                sb.append(ch);
            }
        }
        return sb != null ? sb.toString() : input;
    }
}
