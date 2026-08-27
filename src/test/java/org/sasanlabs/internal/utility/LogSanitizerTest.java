package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\r\ndef"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\rdef"));
    }

    @Test
    void sanitize_removesLineFeed() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\ndef"));
    }

    @Test
    void sanitize_removesTab() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\tdef"));
    }

    @Test
    void sanitize_preservesNormalChars() {
        String normal = "https://example.com/path?a=1&b=2";
        assertEquals(normal, LogSanitizer.sanitize(normal));
    }

    @Test
    void sanitize_nullReturnsEmpty() {
        assertEquals("", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_emptyReturnsEmpty() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_removesNulChar() {
        // NUL (0x00) is an ISO control character
        String input = "a" + (char) 0 + "b";
        assertEquals("ab", LogSanitizer.sanitize(input));
    }

    @Test
    void sanitize_preventsLogInjection() {
        // An attacker could inject fake log entries with newlines
        String malicious = "normal\n[ERROR] Fake log entry injected\r\nMore injection";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals(-1, sanitized.indexOf('\n'));
        assertEquals(-1, sanitized.indexOf('\r'));
    }
}
