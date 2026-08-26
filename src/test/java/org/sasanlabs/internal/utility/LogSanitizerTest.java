package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("sanitize should replace LF characters with underscores")
    void sanitize_replacesLineFeed() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
    }

    @Test
    @DisplayName("sanitize should replace CR characters with underscores")
    void sanitize_replacesCarriageReturn() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
    }

    @Test
    @DisplayName("sanitize should replace CRLF sequences with underscores")
    void sanitize_replacesCrLf() {
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    @DisplayName("sanitize should return the same string if no CR/LF present")
    void sanitize_noChangeWhenClean() {
        assertEquals("clean input", LogSanitizer.sanitize("clean input"));
    }

    @Test
    @DisplayName("sanitize should return 'null' for null input")
    void sanitize_nullInput() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("sanitize should handle empty string")
    void sanitize_emptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
