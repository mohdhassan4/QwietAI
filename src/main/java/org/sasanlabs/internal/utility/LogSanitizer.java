package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to logs, preventing log forging attacks
 * by replacing control characters (CR, LF) that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return and line-feed characters from the input to prevent log forging.
     *
     * @param input the potentially tainted string
     * @return sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace("\r", "").replace("\n", "");
    }
}
