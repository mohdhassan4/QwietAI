package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to logs, preventing log forging /
 * injection attacks (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips CR and LF characters from the input to prevent log injection. Returns an empty string
     * if the input is null.
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        char[] cleaned = value.replaceAll("[\\r\\n\\t]", "_").toCharArray();
        return new String(cleaned);
    }
}
