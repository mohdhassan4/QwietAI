package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to application logs, preventing log
 * forging/injection (CWE-117). Replaces CR, LF, and other control characters with underscores.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips CR, LF, and other control characters from the input to prevent log injection.
     *
     * @param input the user-controlled string to sanitize
     * @return the sanitized string with control characters replaced by underscores, or literal
     *     "null" if input is null
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll("[\\r\\n\\x00-\\x1f\\x7f]", "_");
    }
}
