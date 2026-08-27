package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlineCharacters() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
    }

    @Test
    void sanitize_removesCrLf() {
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    void sanitize_removesTab() {
        assertEquals("col1_col2", LogSanitizer.sanitize("col1\tcol2"));
    }

    @Test
    void sanitize_handlesNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_preservesNormalString() {
        String input = "https://example.com/path?q=hello";
        assertEquals(input, LogSanitizer.sanitize(input));
    }
}
