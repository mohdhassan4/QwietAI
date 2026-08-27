package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled values before they are written to log output, preventing log
 * forging / injection (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return and line-feed characters from the input so that an attacker cannot
     * inject fake log lines.
     *
     * @param value the potentially tainted value
     * @return a safe string with CR/LF removed, or {@code "null"} if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n]", "");
    }
}
