package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled input before writing it to log statements. Prevents log
 * forging (CWE-117) by stripping carriage return, line feed, and other control characters that
 * could be used to inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips CR, LF, and other ASCII control characters from the input string. Returns an empty
     * string when the input is {@code null}.
     *
     * @param input the potentially tainted string
     * @return a sanitized copy safe for inclusion in log messages
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (Character.isISOControl(c)) {
                // Replace other control characters (e.g. \t, \0) with underscore
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
