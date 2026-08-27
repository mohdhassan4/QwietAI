package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlineCharacters() {
        assertEquals("hello_world", LogSanitizer.sanitize("hello\nworld"));
        assertEquals("hello_world", LogSanitizer.sanitize("hello\rworld"));
        assertEquals("hello_world", LogSanitizer.sanitize("hello\r\nworld"));
    }

    @Test
    void sanitize_handlesMultipleNewlines() {
        assertEquals("a_b_c_d", LogSanitizer.sanitize("a\nb\rc\r\nd"));
    }

    @Test
    void sanitize_returnsNullStringForNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_returnsUnchangedWhenNoNewlines() {
        assertEquals("safe input", LogSanitizer.sanitize("safe input"));
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_preventsLogInjection() {
        // An attacker might try to inject a fake log entry
        String malicious = "valid\n2026-08-27 INFO - Fake log entry injected";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals("valid_2026-08-27 INFO - Fake log entry injected", sanitized);
    }
}
