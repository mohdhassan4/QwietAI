package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before writing to log output. Strips CR/LF and other
 * control characters that could allow log forging (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and other ASCII control characters (except tab) with
     * underscore so that attacker-controlled input cannot inject fake log entries.
     *
     * @param value the potentially tainted string
     * @return sanitized string safe for log output, or {@code "null"} if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "_");
    }
}
