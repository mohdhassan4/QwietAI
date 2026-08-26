package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled input before writing it to log statements, preventing log
 * forging/injection attacks (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces characters that could be used for log injection (CR, LF, tab) with their escaped
     * representations so that attacker-controlled data cannot forge new log lines.
     *
     * @param input the potentially tainted string
     * @return a sanitized string safe to embed in a log message, or {@code "null"} if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
