package org.sasanlabs.internal.utility;

/**
 * Utility class for sanitizing user-controlled data before it is written to logs. Prevents log
 * forging / injection (CWE-117) by stripping CR and LF characters that could be used to forge log
 * entries.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return and line-feed characters from the input so that an attacker cannot
     * inject fake log lines.
     *
     * @param value the potentially tainted value to sanitize
     * @return a safe string with newline characters replaced, or {@code "null"} if input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replace("\r", "").replace("\n", "");
    }
}
