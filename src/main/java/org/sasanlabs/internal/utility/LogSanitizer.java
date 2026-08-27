package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled values before they are passed to log statements, preventing
 * log forging / CRLF injection (CWE-117).
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and other ASCII control characters (0x00-0x1F, 0x7F)
     * with an underscore so that attacker-controlled input cannot inject fake log lines.
     *
     * @param value the potentially tainted string
     * @return sanitized string safe for inclusion in log messages, or the literal "null" if value
     *     is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        int length = value.length();
        StringBuilder sb = null;
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                if (sb == null) {
                    sb = new StringBuilder(length);
                    sb.append(value, 0, i);
                }
                sb.append('_');
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb == null ? value : sb.toString();
    }
}
