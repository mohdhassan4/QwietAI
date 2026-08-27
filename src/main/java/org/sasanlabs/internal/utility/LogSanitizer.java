package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before it is written to log messages, preventing log
 * forging (CWE-117) by replacing CR/LF and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a string value for safe inclusion in log output. Replaces carriage return, line
     * feed, and other ASCII control characters with an underscore to prevent log injection.
     *
     * @param value the potentially attacker-controlled value
     * @return a sanitized string safe for logging, or "null" if the input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || (c < 0x20 && c != '\t')) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
