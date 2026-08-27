package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class LogSanitizerTest {

    @Test
    void sanitize_nullInput_returnsNullString() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_emptyInput_returnsEmpty() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_safeInput_returnsUnchanged() {
        String safe = "https://example.com/path?q=value";
        assertEquals(safe, LogSanitizer.sanitize(safe));
    }

    @Test
    void sanitize_newlineCharacters_replacedWithUnderscore() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    void sanitize_tabCharacter_replacedWithUnderscore() {
        assertEquals("col1_col2", LogSanitizer.sanitize("col1\tcol2"));
    }

    @Test
    void sanitize_logForgingAttempt_neutralized() {
        String malicious = "valid\nINFO  [forged] - Fake log entry";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals("valid_INFO  [forged] - Fake log entry", sanitized);
    }

    @Test
    void sanitize_deleteCharacter_replacedWithUnderscore() {
        assertEquals("before_after", LogSanitizer.sanitize("beforeafter"));
    }

    @ParameterizedTest
    @CsvSource({
        "' ',   ' '",
        "'~',   '~'",
        "'!@#$%^&*()', '!@#$%^&*()'",
    })
    void sanitize_printableSpecialChars_unchanged(String input, String expected) {
        assertEquals(expected, LogSanitizer.sanitize(input));
    }

    @Test
    void sanitize_allControlCharsRemoved() {
        StringBuilder input = new StringBuilder();
        for (char c = 0; c < 0x20; c++) {
            input.append(c);
        }
        String sanitized = LogSanitizer.sanitize(input.toString());
        for (int i = 0; i < sanitized.length(); i++) {
            assertEquals('_', sanitized.charAt(i));
        }
    }
}
