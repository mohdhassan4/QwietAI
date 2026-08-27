package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlineCharacters() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\nworld"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\rworld"));
    }

    @Test
    void sanitize_removesCRLF() {
        assertEquals("hello__world", LogSanitizer.sanitize("hello\r\nworld"));
    }

    @Test
    void sanitize_removesTab() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\tworld"));
    }

    @Test
    void sanitize_handlesNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_preservesNormalText() {
        String normal = "https://example.com/path?query=value";
        assertEquals(normal, LogSanitizer.sanitize(normal));
    }

    @Test
    void sanitize_handlesMultipleControlCharacters() {
        assertEquals(
                "fake_log entry_injected_line",
                LogSanitizer.sanitize("fake\nlog entry\r\ninjected\tline"));
    }
}
