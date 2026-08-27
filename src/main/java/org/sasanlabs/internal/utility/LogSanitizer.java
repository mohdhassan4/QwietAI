package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize values before logging, preventing log forging (CWE-117) by stripping
 * carriage-return and line-feed characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces CR and LF characters with underscores so that attacker-controlled input cannot
     * inject fake log entries.
     *
     * @param value the raw value to sanitize (may be {@code null})
     * @return sanitized string safe for logging, or {@code "null"} if input was {@code null}
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n]", "_");
    }
}
