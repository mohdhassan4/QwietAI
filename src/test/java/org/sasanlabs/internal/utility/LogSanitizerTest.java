package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_ShouldReplaceNewlines() {
        assertEquals("first_second", LogSanitizer.sanitize("first\nsecond"));
    }

    @Test
    void sanitize_ShouldReplaceCarriageReturns() {
        assertEquals("first_second", LogSanitizer.sanitize("first\rsecond"));
    }

    @Test
    void sanitize_ShouldReplaceCRLF() {
        assertEquals("first__second", LogSanitizer.sanitize("first\r\nsecond"));
    }

    @Test
    void sanitize_ShouldReplaceTabs() {
        assertEquals("first_second", LogSanitizer.sanitize("first\tsecond"));
    }

    @Test
    void sanitize_ShouldReturnNullString_WhenInputIsNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_ShouldReturnUnchanged_WhenNoControlChars() {
        assertEquals("normalInput", LogSanitizer.sanitize("normalInput"));
    }

    @Test
    void sanitize_ShouldHandleEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
