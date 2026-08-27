package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to log statements, preventing log
 * injection/forging via CRLF characters.
 */
public class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return, newline, and other common control characters from the input so that
     * attacker-controlled data cannot forge log entries.
     */
    public static String sanitize(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
