package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to logs, preventing log forging (CWE-117)
 * by stripping CR/LF and other control characters that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Removes carriage return, line feed, and other control characters from the input so it cannot
     * forge log entries.
     *
     * @param input the potentially tainted string
     * @return sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n' || c == '\t') {
                sb.append('_');
            } else if (Character.isISOControl(c)) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
