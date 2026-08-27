package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("Should return 'null' for null input")
    void sanitizeNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("Should return unchanged string when no control characters present")
    void sanitizeSafeString() {
        assertEquals("hello world", LogSanitizer.sanitize("hello world"));
    }

    @Test
    @DisplayName("Should replace newline characters with underscore")
    void sanitizeNewlines() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    @DisplayName("Should replace all control characters with underscore")
    void sanitizeControlChars() {
        assertEquals("a_b_c", LogSanitizer.sanitize("a" + (char) 1 + "b" + (char) 2 + "c"));
        assertEquals("test_value", LogSanitizer.sanitize("test" + (char) 0 + "value"));
        assertEquals("del_char", LogSanitizer.sanitize("del" + (char) 127 + "char"));
    }

    @Test
    @DisplayName("Should handle log forging attack pattern")
    void sanitizeLogForgingPayload() {
        String malicious = "user\r\nINFO: Fake log entry injected";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals("user__INFO: Fake log entry injected", sanitized);
    }

    @Test
    @DisplayName("Should preserve normal URL characters")
    void sanitizeUrl() {
        String url = "https://example.com/path?key=value&foo=bar#anchor";
        assertEquals(url, LogSanitizer.sanitize(url));
    }

    @Test
    @DisplayName("Should handle empty string")
    void sanitizeEmpty() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
