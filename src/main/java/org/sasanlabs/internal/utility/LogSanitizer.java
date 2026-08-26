package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing it to logs. Prevents log forging /
 * injection (CWE-117) by replacing CR and LF characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return and line-feed characters from the input so that attacker-controlled
     * data cannot inject fake log lines.
     *
     * @param input the untrusted value to sanitize
     * @return a safe string with CR/LF replaced by underscores, or "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace("\r", "_").replace("\n", "_");
    }
}
