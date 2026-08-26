package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1" + '\n' + "line2"));
        assertEquals("line1_line2", LogSanitizer.sanitize("line1" + '\r' + "line2"));
        assertEquals(
                "line1__line2",
                LogSanitizer.sanitize("line1" + '\r' + '\n' + "line2"));
    }

    @Test
    void sanitize_removesTabsAndOtherControlChars() {
        assertEquals("before_after", LogSanitizer.sanitize("before" + '\t' + "after"));
        // Null character (U+0000)
        assertEquals("a_b", LogSanitizer.sanitize("a" + (char) 0 + "b"));
        // Unit separator (U+001F)
        assertEquals("a_b", LogSanitizer.sanitize("a" + (char) 0x1f + "b"));
    }

    @Test
    void sanitize_preservesNormalInput() {
        assertEquals("hello world", LogSanitizer.sanitize("hello world"));
        assertEquals(
                "https://example.com/path?q=1&a=2",
                LogSanitizer.sanitize("https://example.com/path?q=1&a=2"));
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
        // An attacker might try to inject a fake log line
        String malicious = "normal" + '\n' + "2026-08-26 INFO Fake log entry injected";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertFalse(sanitized.contains(String.valueOf('\n')));
        assertFalse(sanitized.contains(String.valueOf('\r')));
    }
}
