package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\r\ndef"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\rdef"));
    }

    @Test
    void sanitize_removesLineFeed() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\ndef"));
    }

    @Test
    void sanitize_nullReturnsLiteral() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_noChangeForCleanInput() {
        assertEquals("clean input", LogSanitizer.sanitize("clean input"));
    }

    @Test
    void sanitize_handlesEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
