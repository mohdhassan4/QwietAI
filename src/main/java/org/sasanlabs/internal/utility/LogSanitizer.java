package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing it to log output. Prevents log forging
 * (CWE-117) by stripping CRLF sequences that could inject fake log entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return and line-feed characters with underscores so that attacker-controlled
     * input cannot inject new log lines.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return input.replace('\r', '_').replace('\n', '_');
    }
}
