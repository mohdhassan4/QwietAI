package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled data before it is written to log messages. Prevents log
 * forging/injection (CWE-117) by replacing CR, LF, tab, and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces all ASCII control characters (0x00-0x1F and 0x7F) with underscores. Returns an empty
     * string when the input is {@code null}.
     *
     * @param value the potentially tainted value
     * @return a sanitized string safe for log output
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[\\x00-\\x1f\\x7f]", "_");
    }
}
