package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled values before writing them to log output, preventing log
 * forging (CRLF injection in logs).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and tab characters with underscores so that
     * attacker-controlled data cannot span multiple log lines.
     *
     * @param value the raw value (may be {@code null})
     * @return sanitized value safe for inclusion in a log message, or {@code "null"} if input is
     *     null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replace('\r', '_').replace('\n', '_').replace('\t', '_');
    }
}
