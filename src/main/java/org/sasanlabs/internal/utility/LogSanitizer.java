package org.sasanlabs.internal.utility;

/**
 * Utility for sanitizing untrusted input before it is written to log statements. Uses an
 * allowlist-based approach: only characters known to be safe for log output are kept; all others
 * (including CR, LF, TAB, backspace, and other control characters) are replaced with an underscore.
 *
 * <p>Assigning the return value to a <b>new local variable</b> before passing it to the logger
 * breaks the taint chain recognized by static analysis tools.
 */
public final class LogSanitizer {

    private static final String SAFE_CHAR_PATTERN = "[^a-zA-Z0-9_.:/@?=&%+\\-~, ]";

    private LogSanitizer() {
        // utility class
    }

    /**
     * Sanitizes the given input by replacing any character not in the allowlist with an underscore.
     *
     * @param input the untrusted value (may be {@code null})
     * @return a sanitized string safe for log output, or the literal string {@code "null"} when
     *     input is {@code null}
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replaceAll(SAFE_CHAR_PATTERN, "_");
    }
}
