package org.sasanlabs.internal.utility;

/**
 * Utility class that sanitizes user-controlled data before it is written to log statements,
 * preventing log forging / injection attacks (CWE-117). Strips carriage-return, line-feed, and
 * other ISO control characters that could be used to inject fake log entries.
 *
 * @author security-remediation
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Sanitizes the given value for safe inclusion in log output. Replaces CR (\r), LF (\n), and
     * other ISO control characters with an underscore.
     *
     * @param value the potentially attacker-controlled string
     * @return a sanitized string safe for logging, or the literal "null" if value is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        int length = value.length();
        StringBuilder sb = null;
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || (Character.isISOControl(c) && c != '\t')) {
                if (sb == null) {
                    sb = new StringBuilder(length);
                    sb.append(value, 0, i);
                }
                sb.append('_');
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb != null ? sb.toString() : value;
    }
}
