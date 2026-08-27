package org.sasanlabs.internal.utility;

/**
 * Utility class to sanitize user-controlled input before writing to logs, preventing log forging
 * (CWE-117) by stripping or replacing CR, LF, and other control characters.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes a string for safe inclusion in log messages. Replaces carriage return (\r) and line
     * feed (\n) characters with safe representations and strips other control characters.
     *
     * @param input the potentially attacker-controlled string
     * @return a sanitized string safe for logging, or "null" if input is null
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r') {
                sb.append("[CR]");
            } else if (c == '\n') {
                sb.append("[LF]");
            } else if (c == '\t') {
                // Allow tabs as-is since they don't enable log forging
                sb.append(c);
            } else if (Character.isISOControl(c)) {
                sb.append("[0x").append(String.format("%02X", (int) c)).append(']');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
