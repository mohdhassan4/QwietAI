package org.sasanlabs.internal.utility;

/**
 * Utility class that sanitizes user-controlled input before it is written to log messages. Prevents
 * log forging/injection (CWE-117) by replacing CRLF characters with safe representations.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return and line-feed characters from the input to prevent log injection.
     *
     * @param value the potentially tainted value
     * @return the sanitized value safe for inclusion in log messages, or {@code "null"} if the
     *     input is {@code null}
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replace("\r", "").replace("\n", "");
    }
}
