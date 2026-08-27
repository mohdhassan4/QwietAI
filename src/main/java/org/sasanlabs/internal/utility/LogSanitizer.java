package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled values before they are interpolated into log messages.
 * Replaces CR, LF, and TAB characters that could be used for log injection/forging.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Strips carriage-return, line-feed, and tab characters from the input, replacing them with
     * underscores so that log entries cannot be forged via injected newlines.
     *
     * @param value the potentially tainted value
     * @return sanitized value safe for log interpolation, or literal "null" if input is null
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
