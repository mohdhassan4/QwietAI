package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled data before writing to logs. Prevents log forging
 * (CWE-117) by stripping CR and LF characters that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes the given value for safe inclusion in log messages by replacing carriage return and
     * line feed characters with underscores.
     *
     * @param value the potentially attacker-controlled value
     * @return sanitized string safe for logging, or "null" if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replace("\r", "_").replace("\n", "_");
    }
}
