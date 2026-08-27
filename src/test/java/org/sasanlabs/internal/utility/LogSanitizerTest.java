package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_nullInput_returnsNullString() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_cleanInput_returnsUnchanged() {
        assertEquals("ZAP-Scanner", LogSanitizer.sanitize("ZAP-Scanner"));
    }

    @Test
    void sanitize_newlinesReplaced() {
        assertEquals("fake_log line", LogSanitizer.sanitize("fake\nlog line"));
        assertEquals("fake_log line", LogSanitizer.sanitize("fake\rlog line"));
        assertEquals("fake__log line", LogSanitizer.sanitize("fake\r\nlog line"));
    }

    @Test
    void sanitize_controlCharsReplaced() {
        // Build string with NUL (0x00), BEL (0x07), ESC (0x1B) at runtime
        String input =
                "a" + (char) 0x00 + "b" + (char) 0x07 + "c" + (char) 0x1B + "d";
        assertEquals("a_b_c_d", LogSanitizer.sanitize(input));
    }

    @Test
    void sanitize_tabPreserved() {
        assertEquals("col1\tcol2", LogSanitizer.sanitize("col1\tcol2"));
    }

    @Test
    void sanitize_emptyString_returnsEmpty() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_logForgingAttempt_neutralized() {
        // An attacker might try to inject a fake log entry
        String malicious = "ZAP\n2026-08-27 INFO  Forged log entry";
        String sanitized = LogSanitizer.sanitize(malicious);
        assertEquals("ZAP_2026-08-27 INFO  Forged log entry", sanitized);
        assertEquals(-1, sanitized.indexOf('\n'));
        assertEquals(-1, sanitized.indexOf('\r'));
    }
}
