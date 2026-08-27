package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before logging, preventing log forging / injection.
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 500;

    private LogSanitizer() {}

    /**
     * Strips CR, LF, and TAB characters and truncates the result to a safe maximum length.
     *
     * @param input the potentially tainted string
     * @return a sanitized string safe for inclusion in log messages
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        String cleaned = input.replaceAll("[\\r\\n\\t]", "");
        if (cleaned.length() > MAX_LENGTH) {
            cleaned = cleaned.substring(0, MAX_LENGTH);
        }
        return cleaned;
    }
}
