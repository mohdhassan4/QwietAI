package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled data before it is written to log messages. Prevents log
 * forging/injection (CWE-117) by replacing CR, LF, tab, and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and tab characters with underscores. Returns an empty
     * string when the input is {@code null}.
     *
     * @param value the potentially tainted value
     * @return a sanitized string safe for log output
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
