package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    void sanitize_removesControlCharacters() {
        // SOH (0x01) and BEL (0x07) should be replaced with underscore
        String withSoh = "abc" + (char) 1 + "def";
        String withBel = "abc" + (char) 7 + "def";
        assertEquals("abc_def", LogSanitizer.sanitize(withSoh));
        assertEquals("abc_def", LogSanitizer.sanitize(withBel));
    }

    @Test
    void sanitize_preservesTabs() {
        assertEquals("abc\tdef", LogSanitizer.sanitize("abc\tdef"));
    }

    @Test
    void sanitize_preservesNormalText() {
        assertEquals("hello world", LogSanitizer.sanitize("hello world"));
        assertEquals(
                "https://example.com/path?q=1",
                LogSanitizer.sanitize("https://example.com/path?q=1"));
    }

    @Test
    void sanitize_handlesNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_handlesEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_preventsLogForging() {
        // An attacker tries to inject a fake log entry
        String malicious = "normal\n2026-08-26 INFO - Fake log entry injected";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals(
                "normal_2026-08-26 INFO - Fake log entry injected", sanitized);
    }
}
