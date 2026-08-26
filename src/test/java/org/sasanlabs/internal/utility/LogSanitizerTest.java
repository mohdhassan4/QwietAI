package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlineCharacters() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\ndef"));
        assertEquals("abcdef", LogSanitizer.sanitize("abc\rdef"));
        assertEquals("abcdef", LogSanitizer.sanitize("abc\r\ndef"));
    }

    @Test
    void sanitize_returnsUnchangedWhenNoControlChars() {
        assertEquals("clean input", LogSanitizer.sanitize("clean input"));
    }

    @Test
    void sanitize_handlesNullInput() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_handlesEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_preventsLogForging() {
        // An attacker might try to inject a fake log line
        String malicious = "valid\n2026-08-26 INFO - Fake log entry injected";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals("valid2026-08-26 INFO - Fake log entry injected", sanitized);
    }
}
