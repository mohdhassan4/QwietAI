package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled values before writing them to application logs. Strips
 * carriage-return, line-feed, and other ASCII control characters to prevent log forging / log
 * injection attacks.
 *
 * @author security-remediation
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces CR, LF, and other ASCII control characters (0x00-0x1F, 0x7F) with an underscore so
     * that attacker-controlled data cannot inject fake log lines or corrupt log formatting.
     *
     * @param value the potentially tainted value; may be {@code null}
     * @return sanitized string safe for inclusion in log messages, or {@code "null"} if input is
     *     null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\x00-\\x1F\\x7F]", "_");
    }
}
