package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_ShouldReturnNullString_WhenInputIsNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_ShouldReturnSameString_WhenNoNewlines() {
        assertEquals("safe input", LogSanitizer.sanitize("safe input"));
    }

    @Test
    void sanitize_ShouldStripLineFeed() {
        assertEquals("line1line2", LogSanitizer.sanitize("line1\nline2"));
    }

    @Test
    void sanitize_ShouldStripCarriageReturn() {
        assertEquals("line1line2", LogSanitizer.sanitize("line1\rline2"));
    }

    @Test
    void sanitize_ShouldStripCRLF() {
        assertEquals("line1line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    void sanitize_ShouldHandleMultipleNewlines() {
        assertEquals(
                "fakelog entry injected",
                LogSanitizer.sanitize("\nfakelog\r entry\r\n injected\n"));
    }
}
