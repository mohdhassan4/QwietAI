package org.sasanlabs.internal.utility;

/**
 * Utility class that sanitizes user-controlled input before it is written to log messages. Prevents
 * log forging/injection (CWE-117) by removing CRLF characters and other control characters that
 * could be used for log injection attacks.
 */
public final class LogSanitizer {

    private static final int MAX_LOG_VALUE_LENGTH = 256;

    private LogSanitizer() {}

    /**
     * Removes carriage-return, line-feed, tab, and other ASCII control characters from the input
     * to prevent log injection. Also truncates excessively long values.
     *
     * @param value the potentially tainted value
     * @return the sanitized value safe for inclusion in log messages, or {@code "null"} if the
     *     input is {@code null}
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        String cleaned = value.replaceAll("[\\r\\n\\t]", "_")
                .replaceAll("[\\x00-\\x1F\\x7F]", "");
        if (cleaned.length() > MAX_LOG_VALUE_LENGTH) {
            cleaned = cleaned.substring(0, MAX_LOG_VALUE_LENGTH) + "...";
        }
        return cleaned;
    }
}
