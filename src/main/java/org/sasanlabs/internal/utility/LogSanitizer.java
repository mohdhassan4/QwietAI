package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing it to logs, preventing log forging
 * (CWE-117). Strips carriage-return and line-feed characters that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces CR and LF characters (and their combinations) with an underscore so that
     * attacker-controlled input cannot inject new log lines.
     *
     * @param input the untrusted value to sanitize
     * @return sanitized string safe for logging, or {@code "null"} if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace("\r\n", "_").replace("\r", "_").replace("\n", "_");
    }
}
