package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("sanitize: returns 'null' literal for null input")
    void sanitize_NullInput() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("sanitize: returns empty string unchanged")
    void sanitize_EmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    @DisplayName("sanitize: returns safe string unchanged")
    void sanitize_SafeString() {
        String safe = "https://example.com/path?q=value";
        assertEquals(safe, LogSanitizer.sanitize(safe));
    }

    @Test
    @DisplayName("sanitize: replaces CR and LF with underscore")
    void sanitize_CrLfReplaced() {
        assertEquals(
                "line1_line2_line3",
                LogSanitizer.sanitize("line1\nline2\rline3"));
    }

    @Test
    @DisplayName("sanitize: replaces CRLF pair with underscores")
    void sanitize_CrlfPair() {
        assertEquals("first__second", LogSanitizer.sanitize("first\r\nsecond"));
    }

    @Test
    @DisplayName("sanitize: replaces tab and other control chars")
    void sanitize_ControlChars() {
        assertEquals("a_b_c", LogSanitizer.sanitize("a\rb\nc"));
    }

    @Test
    @DisplayName("sanitize: replaces DEL (0x7F) with underscore")
    void sanitize_Del() {
        String input = "before" + (char) 0x7F + "after";
        assertEquals("before_after", LogSanitizer.sanitize(input));
    }

    @Test
    @DisplayName("sanitize: preserves space and printable ASCII")
    void sanitize_SpacePreserved() {
        assertEquals("hello world", LogSanitizer.sanitize("hello world"));
    }

    @Test
    @DisplayName("sanitize: prevents log forging attack pattern")
    void sanitize_LogForgingPrevented() {
        String malicious = "normal\n[ERROR] Fake log entry injected by attacker";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals(-1, sanitized.indexOf('\n'));
        assertEquals(-1, sanitized.indexOf('\r'));
        assertEquals(
                "normal_[ERROR] Fake log entry injected by attacker",
                sanitized);
    }
}
