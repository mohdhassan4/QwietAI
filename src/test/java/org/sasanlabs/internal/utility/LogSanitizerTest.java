package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitizesNewline() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\nline2"));
    }

    @Test
    void sanitizesCarriageReturn() {
        assertEquals("line1_line2", LogSanitizer.sanitize("line1\rline2"));
    }

    @Test
    void sanitizesCRLF() {
        assertEquals("line1__line2", LogSanitizer.sanitize("line1\r\nline2"));
    }

    @Test
    void returnsNullString() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void returnsSafeStringUnchanged() {
        assertEquals("safe-input_123", LogSanitizer.sanitize("safe-input_123"));
    }

    @Test
    void sanitizesLogInjectionPayload() {
        String payload = "value\n2026-08-26 INFO Fake log entry";
        assertEquals("value_2026-08-26 INFO Fake log entry", LogSanitizer.sanitize(payload));
    }
}
