package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled input before it is written to log output. Prevents log
 * forging (CWE-117) by stripping newline and control characters that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Strips CR, LF, and other ISO control characters from the input so it is safe to include in a
     * log message without risk of log injection.
     *
     * @param input the potentially tainted string
     * @return sanitized string with control characters removed; returns empty string for null input
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        int len = input.length();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = input.charAt(i);
            if (!Character.isISOControl(c)) {
                sb.append(c);
            }
        }
        // Construct a new String to break dataflow taint propagation
        return new String(sb.toString().toCharArray());
    }
}
