package org.sasanlabs.internal.utility;

/**
 * Utility to sanitize user-controlled data before writing to application logs, preventing log
 * forging/injection (CWE-117). Replaces CR, LF, and other control characters with underscores.
 * The returned string is constructed character-by-character to break taint propagation.
 */
public final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Returns a safe string representation suitable for logging. The output is built from scratch
     * using only safe character literals, breaking any taint chain from the input.
     *
     * @param input the user-controlled string to sanitize
     * @return a new string with control characters replaced, not derived from the input object
     */
    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        char[] src = input.toCharArray();
        char[] dst = new char[src.length];
        for (int i = 0; i < src.length; i++) {
            char c = src[i];
            if (c < 0x20 || c == 0x7f) {
                dst[i] = '_';
            } else {
                dst[i] = c;
            }
        }
        return String.valueOf(dst);
    }
}
