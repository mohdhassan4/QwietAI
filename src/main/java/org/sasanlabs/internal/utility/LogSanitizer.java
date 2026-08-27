package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled strings before passing them to log statements. Prevents log
 * forging (CWE-117) by replacing CRLF characters that could inject fake log entries.
 */
public class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return and line-feed characters with underscores so that attacker-controlled
     * data cannot inject new log lines.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return input.replace('\r', '_').replace('\n', '_');
    }
}
