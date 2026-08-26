package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitizeForLog_nullInput_returnsNullString() {
        assertEquals("null", LogSanitizer.sanitizeForLog(null));
    }

    @Test
    void sanitizeForLog_cleanInput_returnsUnchanged() {
        assertEquals("hello world", LogSanitizer.sanitizeForLog("hello world"));
    }

    @Test
    void sanitizeForLog_inputWithCR_replacesCR() {
        assertEquals("line1[CR]line2", LogSanitizer.sanitizeForLog("line1\rline2"));
    }

    @Test
    void sanitizeForLog_inputWithLF_replacesLF() {
        assertEquals("line1[LF]line2", LogSanitizer.sanitizeForLog("line1\nline2"));
    }

    @Test
    void sanitizeForLog_inputWithCRLF_replacesBoth() {
        assertEquals("line1[CR][LF]line2", LogSanitizer.sanitizeForLog("line1\r\nline2"));
    }

    @Test
    void sanitizeForLog_multipleCRLF_replacesAll() {
        assertEquals(
                "a[LF]b[CR]c[CR][LF]d",
                LogSanitizer.sanitizeForLog("a\nb\rc\r\nd"));
    }

    @Test
    void sanitizeForLog_emptyString_returnsEmpty() {
        assertEquals("", LogSanitizer.sanitizeForLog(""));
    }

    @Test
    void sanitizeForLog_logInjectionAttempt_sanitized() {
        String malicious = "user\n2026-08-26 INFO Fake log entry injected";
        String sanitized = LogSanitizer.sanitizeForLog(malicious);
        assertEquals("user[LF]2026-08-26 INFO Fake log entry injected", sanitized);
    }
}
