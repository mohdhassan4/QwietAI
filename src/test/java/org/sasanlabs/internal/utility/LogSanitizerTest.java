package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("sanitizeForLog: should return 'null' string for null input")
    void sanitizeForLog_NullInput() {
        assertEquals("null", LogSanitizer.sanitizeForLog(null));
    }

    @Test
    @DisplayName("sanitizeForLog: should return empty string for empty input")
    void sanitizeForLog_EmptyInput() {
        assertEquals("", LogSanitizer.sanitizeForLog(""));
    }

    @Test
    @DisplayName("sanitizeForLog: should pass through safe strings unchanged")
    void sanitizeForLog_SafeInput() {
        assertEquals("hello world", LogSanitizer.sanitizeForLog("hello world"));
    }

    @Test
    @DisplayName("sanitizeForLog: should escape newline characters")
    void sanitizeForLog_NewlineInjection() {
        assertEquals(
                "first\\nsecond", LogSanitizer.sanitizeForLog("first\nsecond"));
    }

    @Test
    @DisplayName("sanitizeForLog: should escape carriage return characters")
    void sanitizeForLog_CarriageReturnInjection() {
        assertEquals(
                "first\\rsecond", LogSanitizer.sanitizeForLog("first\rsecond"));
    }

    @Test
    @DisplayName("sanitizeForLog: should escape CRLF sequences")
    void sanitizeForLog_CrlfInjection() {
        assertEquals(
                "first\\r\\nsecond", LogSanitizer.sanitizeForLog("first\r\nsecond"));
    }

    @Test
    @DisplayName("sanitizeForLog: should escape tab characters")
    void sanitizeForLog_TabInjection() {
        assertEquals(
                "first\\tsecond", LogSanitizer.sanitizeForLog("first\tsecond"));
    }

    @Test
    @DisplayName("sanitizeForLog: should handle combined injection attempt")
    void sanitizeForLog_CombinedInjection() {
        String malicious = "admin\r\nINFO  Fake log entry\ttab";
        String expected = "admin\\r\\nINFO  Fake log entry\\ttab";
        assertEquals(expected, LogSanitizer.sanitizeForLog(malicious));
    }
}
