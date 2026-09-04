package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class LogSanitizationUtilsTest {

    @Test
    void nullValueIsRepresentedAsNull() {
        assertEquals("null", LogSanitizationUtils.sanitize(null));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                "admin",
                "https://gist.githubusercontent.com/raw/projects",
                "tool-name_1 with spaces and symbols !\"#$%&'()*+,-./:;<=>?@[]^`{|}~"
            })
    void harmlessValuesAreKeptAsIs(String value) {
        assertEquals(value, LogSanitizationUtils.sanitize(value));
    }

    /**
     * Every one of these characters could either terminate the current log record or hide a part of
     * its content, hence none of them must reach the logs.
     */
    @ParameterizedTest
    @ValueSource(
            chars = {
                '\n', // line feed
                '\r', // carriage return
                '\t', // tabulation
                '\u0000', // null
                '\u000b', // vertical tabulation
                '\u001b', // escape, ie the prefix of the terminal escape sequences
                '\u007f', // delete
                '\u0085', // next line
                '\u2028', // unicode line separator
                '\u2029', // unicode paragraph separator
                '\u200e' // left to right mark
            })
    void recordSplittingCharactersAreNeutralized(char character) {
        assertEquals(
                "admin_forged", LogSanitizationUtils.sanitize("admin" + character + "forged"));
    }

    @Test
    void everyLineBreakOfAMultiLineValueIsNeutralized() {
        assertEquals("line1_line2__line3", LogSanitizationUtils.sanitize("line1\nline2\r\nline3"));
    }

    @Test
    void aForgedLogRecordCannotBeInjected() {
        String sanitized =
                LogSanitizationUtils.sanitize("admin\r\n2024-01-01 INFO forged log record");

        assertEquals("admin__2024-01-01 INFO forged log record", sanitized);
    }

    @Test
    void excessivelyLongValuesAreTruncated() {
        String value = "a".repeat(LogSanitizationUtils.MAX_LOGGED_LENGTH + 100);

        assertEquals(
                "a".repeat(LogSanitizationUtils.MAX_LOGGED_LENGTH) + "...(truncated)",
                LogSanitizationUtils.sanitize(value));
    }

    @Test
    void valuesOfTheMaximumLengthAreNotTruncated() {
        String value = "a".repeat(LogSanitizationUtils.MAX_LOGGED_LENGTH);

        assertEquals(value, LogSanitizationUtils.sanitize(value));
    }
}
