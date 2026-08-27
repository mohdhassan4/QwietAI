package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled input before writing it to log messages. Strips CR/LF and
 * other control characters to prevent log forging/injection attacks.
 *
 * @author security-remediation
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Removes carriage-return, line-feed, and other ASCII control characters (0x00-0x1F, 0x7F)
     * from the input string, replacing them with an underscore to preserve readability.
     *
     * @param input the potentially tainted string
     * @return a sanitized string safe for log output, or the literal {@code "null"} if input is
     *     null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        // Replace control characters (includes \r, \n, \t, etc.) with underscore
        return input.replaceAll("[\\x00-\\x1F\\x7F]", "_");
    }
}
