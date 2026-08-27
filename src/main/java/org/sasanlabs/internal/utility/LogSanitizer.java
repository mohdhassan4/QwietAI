package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled input before writing to log output, preventing log
 * forging (CWE-117) by stripping CR/LF and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes input for safe inclusion in log messages by replacing carriage return (\r), line
     * feed (\n), and other ASCII control characters with an underscore. Returns "(null)" for null
     * input.
     *
     * @param input the potentially tainted user input
     * @return a single-line sanitized string safe for logging
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "(null)";
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
