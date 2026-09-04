package org.sasanlabs.internal.utility;

/**
 * Utility class neutralizing the user controlled values which are written to the application logs,
 * hence avoiding log injection, also known as log forging (CWE-117).
 *
 * <p>Line breaks, other control characters and the unicode separators are replaced by an underscore
 * so that a user provided value can neither terminate the current log record nor forge additional
 * ones, and overly long values are truncated so that a single record stays readable.
 */
public final class LogSanitizationUtils {

    /** Maximum number of characters kept from a user controlled value. */
    static final int MAX_LOGGED_LENGTH = 256;

    private static final String NULL_VALUE = "null";

    private static final String TRUNCATION_MARKER = "...(truncated)";

    private static final char REPLACEMENT_CHARACTER = '_';

    private LogSanitizationUtils() {}

    /**
     * Neutralizes a user controlled value so that it can safely be logged as a single log record.
     *
     * @param value the user controlled value, possibly {@code null}.
     * @return the value without any character able to forge or split a log record, {@code "null"}
     *     when the provided value is {@code null}.
     */
    public static String sanitize(String value) {
        if (value == null) {
            return NULL_VALUE;
        }
        int keptLength = Math.min(value.length(), MAX_LOGGED_LENGTH);
        StringBuilder sanitized = new StringBuilder(keptLength + TRUNCATION_MARKER.length());
        for (int i = 0; i < keptLength; i++) {
            char character = value.charAt(i);
            sanitized.append(isSafeToLog(character) ? character : REPLACEMENT_CHARACTER);
        }
        if (value.length() > MAX_LOGGED_LENGTH) {
            sanitized.append(TRUNCATION_MARKER);
        }
        return sanitized.toString();
    }

    private static boolean isSafeToLog(char character) {
        // the ISO control characters, eg CR, LF, TAB and NUL, along with the unicode separators and
        // format characters, are the ones able to split a log record or to hide its content
        int type = Character.getType(character);
        return !Character.isISOControl(character)
                && type != Character.LINE_SEPARATOR
                && type != Character.PARAGRAPH_SEPARATOR
                && type != Character.FORMAT;
    }
}
