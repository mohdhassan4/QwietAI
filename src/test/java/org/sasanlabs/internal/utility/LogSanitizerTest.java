package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_ShouldReturnNull_WhenInputIsNull() {
        assertNull(LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_ShouldReturnSameString_WhenNoCRLF() {
        assertEquals("hello world", LogSanitizer.sanitize("hello world"));
    }

    @Test
    void sanitize_ShouldReplaceNewline() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
    }

    @Test
    void sanitize_ShouldReplaceCarriageReturn() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
    }

    @Test
    void sanitize_ShouldReplaceCRLF() {
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    void sanitize_ShouldHandleEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
