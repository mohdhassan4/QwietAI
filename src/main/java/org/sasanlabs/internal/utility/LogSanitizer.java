package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to logs, preventing log
 * forging/injection (CWE-117) by stripping CR/LF and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Removes carriage-return, line-feed, and other ASCII control characters (except tab) from the
     * input so that attacker-controlled data cannot inject fake log entries.
     *
     * @param input the potentially tainted string
     * @return sanitized string safe for logging, or {@code "null"} if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
    }
}
