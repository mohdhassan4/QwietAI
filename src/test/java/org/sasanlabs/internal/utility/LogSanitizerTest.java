package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("sanitize: should strip carriage-return characters")
    void sanitize_stripsCR() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\rdef"));
    }

    @Test
    @DisplayName("sanitize: should strip line-feed characters")
    void sanitize_stripsLF() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\ndef"));
    }

    @Test
    @DisplayName("sanitize: should strip CRLF sequences")
    void sanitize_stripsCRLF() {
        assertEquals("abcdef", LogSanitizer.sanitize("abc\r\ndef"));
    }

    @Test
    @DisplayName("sanitize: should return input unchanged when no CRLF present")
    void sanitize_noOpForCleanInput() {
        assertEquals("clean input", LogSanitizer.sanitize("clean input"));
    }

    @Test
    @DisplayName("sanitize: should return 'null' for null input")
    void sanitize_handlesNull() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("sanitize: should handle empty string")
    void sanitize_handlesEmpty() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    @DisplayName("sanitize: should strip multiple newlines in forged log entry")
    void sanitize_stripsForgedLogEntry() {
        String forged = "normal\r\nINFO  Forged log entry\r\n";
        assertEquals("INFO  Forged log entry", LogSanitizer.sanitize(forged));
    }
}
