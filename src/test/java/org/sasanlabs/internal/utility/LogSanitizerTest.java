package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("first_second", LogSanitizer.sanitize("first\nsecond"));
    }

    @Test
    void sanitize_removesCarriageReturns() {
        assertEquals("first_second", LogSanitizer.sanitize("first\rsecond"));
    }

    @Test
    void sanitize_removesCRLF() {
        assertEquals("first__second", LogSanitizer.sanitize("first\r\nsecond"));
    }

    @Test
    void sanitize_nullReturnsEmpty() {
        assertEquals("", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_cleanStringUnchanged() {
        assertEquals("https://example.com/path", LogSanitizer.sanitize("https://example.com/path"));
    }
}
