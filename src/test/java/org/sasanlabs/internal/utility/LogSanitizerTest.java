package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\rworld"));
    }

    @Test
    void sanitize_removesLineFeed() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\nworld"));
    }

    @Test
    void sanitize_removesCRLF() {
        assertEquals("hello__world", LogSanitizer.sanitize("hello\r\nworld"));
    }

    @Test
    void sanitize_returnsNullForNull() {
        assertNull(LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_preservesSafeString() {
        String safe = "https://example.com/path?q=value";
        assertEquals(safe, LogSanitizer.sanitize(safe));
    }

    @Test
    void sanitize_handlesMultipleNewlines() {
        assertEquals("a_b_c_d", LogSanitizer.sanitize("a\nb\rc\r\nd"));
    }
}
