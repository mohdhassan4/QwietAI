package org.sasanlabs.internal.utility;

/**
 * Utility class for sanitizing user-controlled data before writing it to log output. Prevents log
 * forging (CWE-117) by replacing carriage return, line feed, and other control characters with safe
 * representations.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a string for safe inclusion in log messages by replacing control characters (ASCII
     * 0x00-0x1F and 0x7F) with underscores. Returns the literal string "null" when the input is
     * null.
     *
     * @param input the potentially attacker-controlled string
     * @return a sanitized string safe for logging
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
