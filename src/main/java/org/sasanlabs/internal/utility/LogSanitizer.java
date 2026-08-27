package org.sasanlabs.internal.utility;

/**
 * Utility class for sanitizing user-controlled data before it is written to logs. Prevents log
 * forging / injection (CWE-117) by stripping CR and LF characters that could be used to forge log
 * entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return, line-feed, and other control characters from the input so that an
     * attacker cannot inject fake log lines or manipulate log output (CWE-117).
     *
     * @param value the potentially tainted value to sanitize
     * @return a safe string with control characters removed, or {@code "null"} if input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "");
    }

    /**
     * Sanitizes an arbitrary object's string representation for safe log output.
     *
     * @param value the object whose toString() should be sanitized
     * @return a safe string with control characters removed, or {@code "null"} if input is null
     */
    public static String sanitize(Object value) {
        if (value == null) {
            return "null";
        }
        return sanitize(value.toString());
    }
}
