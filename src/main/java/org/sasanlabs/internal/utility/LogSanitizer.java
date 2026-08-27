package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled input before logging, preventing log forging (CWE-117)
 * via CRLF injection.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a string for safe inclusion in log messages by replacing carriage return, line feed,
     * and other control characters with underscores.
     *
     * @param input the potentially tainted string
     * @return a sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n' || (c < 0x20 && c != '\t')) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
