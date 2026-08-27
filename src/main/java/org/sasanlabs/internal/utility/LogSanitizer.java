package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing user-controlled data before writing to logs. Strips CR/LF and other
 * control characters to prevent log forging/injection (CWE-117).
 *
 * @author security-remediation
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Replaces carriage-return, line-feed, and other ASCII control characters (except TAB) with
     * underscore so that attacker-controlled input cannot forge log entries.
     *
     * @param value the potentially tainted string
     * @return sanitized string safe for inclusion in log messages, or "null" if input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n') {
                sb.append('_');
            } else if (c < 0x20 && c != '\t') {
                // Replace other control characters (NUL, BEL, ESC, etc.)
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
