package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled input before writing to log messages. Strips CR/LF and
 * other control characters to prevent log forging/injection attacks.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Removes carriage return, line feed, and other ASCII control characters from the input string
     * to prevent log injection.
     *
     * @param input the potentially tainted input
     * @return sanitized string safe for logging, or "null" if input is null
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
