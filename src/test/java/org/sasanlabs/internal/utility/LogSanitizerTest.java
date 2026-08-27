package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_ShouldReplaceNewlineCharacters() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\nworld"));
        assertEquals("hello_world", LogSanitizer.sanitize("hello\rworld"));
        assertEquals("hello__world", LogSanitizer.sanitize("hello\r\nworld"));
    }

    @Test
    void sanitize_ShouldReplaceTabCharacters() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\tworld"));
    }

    @Test
    void sanitize_ShouldReturnNullStringForNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_ShouldNotModifySafeStrings() {
        assertEquals("safe-input_123", LogSanitizer.sanitize("safe-input_123"));
        assertEquals("https://example.com/path?q=1", LogSanitizer.sanitize("https://example.com/path?q=1"));
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_ShouldHandleMultipleControlCharacters() {
        assertEquals("line1_line2_line3_", LogSanitizer.sanitize("line1\nline2\rline3\t"));
    }
}
