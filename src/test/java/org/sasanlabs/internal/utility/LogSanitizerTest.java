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
    void sanitizeForLog_removesTabs() {
        assertEquals("hello_world", LogSanitizer.sanitizeForLog("hello\tworld"));
    }

    @Test
    void sanitizeForLog_handlesNull() {
        assertEquals("null", LogSanitizer.sanitizeForLog(null));
    }

    @Test
    void sanitizeForLog_preservesSafeString() {
        String safe = "https://example.com/path?q=1";
        assertEquals(safe, LogSanitizer.sanitizeForLog(safe));
    }

    @Test
    void sanitizeForLog_preventsLogForging() {
        // An attacker tries to forge a fake log entry
        String malicious = "normal\n2026-08-27 INFO - Fake log entry injected";
        String sanitized = LogSanitizer.sanitizeForLog(malicious);
        assertEquals("normal_2026-08-27 INFO - Fake log entry injected", sanitized);
    }
}
