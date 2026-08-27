package org.sasanlabs.internal.utility;

/**
 * Utility class for sanitizing untrusted input before writing it to log statements. Prevents log
 * forging (CWE-117) by replacing CR, LF, and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes the given input for safe inclusion in log messages. Replaces carriage return (\r),
     * line feed (\n), and tab (\t) characters with underscores to prevent log injection.
     *
     * @param input the untrusted input string
     * @return sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace('\r', '_').replace('\n', '_').replace('\t', '_');
    }
}
