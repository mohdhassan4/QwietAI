package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("Should strip carriage-return characters")
    void sanitize_removesCarriageReturn() {
        assertEquals("foobar", LogSanitizer.sanitize("foo\rbar"));
    }

    @Test
    @DisplayName("Should strip line-feed characters")
    void sanitize_removesLineFeed() {
        assertEquals("foobar", LogSanitizer.sanitize("foo\nbar"));
    }

    @Test
    @DisplayName("Should strip CRLF sequences")
    void sanitize_removesCRLF() {
        assertEquals("foobar", LogSanitizer.sanitize("foo\r\nbar"));
    }

    @Test
    @DisplayName("Should strip multiple embedded newlines")
    void sanitize_removesMultipleNewlines() {
        String input = "first\nsecond\rthird\r\nfourth";
        assertEquals("firstsecondthirdfourth", LogSanitizer.sanitize(input));
    }

    @Test
    @DisplayName("Should return unchanged string when no CRLF present")
    void sanitize_noOpWhenClean() {
        assertEquals("clean value", LogSanitizer.sanitize("clean value"));
    }

    @Test
    @DisplayName("Should return 'null' string for null input")
    void sanitize_nullInput() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("Should handle empty string")
    void sanitize_emptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
