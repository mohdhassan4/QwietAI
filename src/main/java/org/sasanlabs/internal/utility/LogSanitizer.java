package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize untrusted input before writing to log statements, preventing log
 * forging / log injection attacks (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips control characters (newlines, carriage returns, tabs, and other ASCII control chars)
     * from the input so that an attacker cannot inject fake log entries.
     *
     * @param input the untrusted string to sanitize
     * @return a sanitized string safe for logging, or "[null]" if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "[null]";
        }
        // Replace any character in the C0 control range (0x00-0x1F) and DEL (0x7F)
        // with an underscore to prevent log injection.
        return input.replaceAll("[\\x00-\\x1F\\x7F]", "_");
    }
}
