package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\nworld"));
    }

    @Test
    void sanitize_removesCarriageReturns() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\rworld"));
    }

    @Test
    void sanitize_removesCRLF() {
        assertEquals("hello__world", LogSanitizer.sanitize("hello\r\nworld"));
    }

    @Test
    void sanitize_preservesNormalInput() {
        assertEquals("normal input", LogSanitizer.sanitize("normal input"));
    }

    @Test
    void sanitize_handlesNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_handlesEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
