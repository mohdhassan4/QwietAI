package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing it to log output. Prevents log
 * forging/injection (CWE-117) by replacing CR, LF, and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and other ISO control characters with an underscore so
     * that attacker-controlled input cannot inject fake log lines.
     *
     * @param input the potentially tainted string
     * @return a sanitized copy safe for logging, or the literal {@code "null"} if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        int length = input.length();
        StringBuilder sb = null;
        for (int i = 0; i < length; i++) {
            char c = input.charAt(i);
            if (Character.isISOControl(c)) {
                if (sb == null) {
                    sb = new StringBuilder(length);
                    sb.append(input, 0, i);
                }
                sb.append('_');
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb == null ? input : sb.toString();
    }
}
