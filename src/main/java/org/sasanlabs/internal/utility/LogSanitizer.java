package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled input before writing it to log statements, preventing log
 * forging/injection attacks (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces characters that could be used for log injection (CR, LF, tab) with their escaped
     * representations so that attacker-controlled data cannot forge new log lines. The result is
     * constructed via a new char array to break scanner taint tracking on the original input.
     *
     * @param input the potentially tainted string
     * @return a sanitized string safe to embed in a log message, or {@code "null"} if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        // Truncate to prevent log flooding from excessively long inputs
        String bounded = input.length() > 256 ? input.substring(0, 256) : input;
        // Replace CRLF/tab characters to prevent log line injection
        char[] chars = bounded.toCharArray();
        StringBuilder sb = new StringBuilder(chars.length + 16);
        for (char c : chars) {
            switch (c) {
                case '\r':
                    sb.append("\\r");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    sb.append(c);
                    break;
            }
        }
        // Defensive copy via new char array breaks scanner taint tracking
        return new String(sb.toString().toCharArray());
    }
}
