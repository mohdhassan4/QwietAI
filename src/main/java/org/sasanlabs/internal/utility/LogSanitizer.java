package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to log statements, preventing log
 * forging/injection attacks (CWE-117). Strips CR and LF characters that could be used to inject
 * fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {
        // utility class
    }

    /**
     * Sanitizes the given input for safe inclusion in log messages by replacing carriage return and
     * line feed characters with safe representations.
     *
     * @param input the potentially attacker-controlled string
     * @return a sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace("\r", "[CR]").replace("\n", "[LF]");
    }
}
