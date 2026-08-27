package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("sanitize: Should replace CR, LF, and TAB with underscores")
    void sanitize_ReplacesCrlfAndTab() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
        assertEquals("col1_col2", LogSanitizer.sanitize("col1\tcol2"));
    }

    @Test
    @DisplayName("sanitize: Should return null for null input")
    void sanitize_NullInput() {
        assertNull(LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("sanitize: Should return input unchanged when no control characters present")
    void sanitize_CleanInput() {
        assertEquals("safe-value_123", LogSanitizer.sanitize("safe-value_123"));
        assertEquals("https://example.com/path?q=1", LogSanitizer.sanitize("https://example.com/path?q=1"));
    }

    @Test
    @DisplayName("sanitize: Should prevent log forging attack payloads")
    void sanitize_LogForgingPayload() {
        String malicious = "normal\n[ERROR] Fake log entry injected\nMore fake";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertFalse(sanitized.contains("\n"));
        assertFalse(sanitized.contains("\r"));
        assertEquals("normal_[ERROR] Fake log entry injected_More fake", sanitized);
    }
}
