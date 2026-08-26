package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to logs, preventing log
 * forging/injection attacks (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips CR and LF characters from the input to prevent log injection. Null input is returned
     * as the literal string "null" to remain safe in log interpolation.
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace("\r", "").replace("\n", "");
    }
}
