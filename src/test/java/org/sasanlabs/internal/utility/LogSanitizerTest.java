package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitizeForLog_removesNewlines() {
        assertEquals("hello_world", LogSanitizer.sanitizeForLog("hello\nworld"));
    }

    @Test
    void sanitizeForLog_removesCarriageReturn() {
        assertEquals("hello_world", LogSanitizer.sanitizeForLog("hello\rworld"));
    }

    @Test
    void sanitizeForLog_removesCRLF() {
        assertEquals("hello__world", LogSanitizer.sanitizeForLog("hello\r\nworld"));
    }

    @Test
    void sanitizeForLog_removesTab() {
        assertEquals("hello_world", LogSanitizer.sanitizeForLog("hello\tworld"));
    }

    @Test
    void sanitizeForLog_handlesNull() {
        assertEquals("null", LogSanitizer.sanitizeForLog(null));
    }

    @Test
    void sanitizeForLog_preservesSafeString() {
        String safe = "https://example.com/path?q=value";
        assertEquals(safe, LogSanitizer.sanitizeForLog(safe));
    }

    @Test
    void sanitizeForLog_handlesEmptyString() {
        assertEquals("", LogSanitizer.sanitizeForLog(""));
    }
}
