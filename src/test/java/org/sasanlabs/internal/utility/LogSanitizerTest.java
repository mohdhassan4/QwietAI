package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    @DisplayName("sanitize: Should strip CR and LF characters from input")
    void sanitize_StripsCrLf() {
        assertEquals("abc", LogSanitizer.sanitize("a\r\nb\nc"));
        assertEquals("injectedline", LogSanitizer.sanitize("injected\nline"));
        assertEquals("injectedline", LogSanitizer.sanitize("injected\rline"));
        assertEquals("injectedline", LogSanitizer.sanitize("injected\r\nline"));
    }

    @Test
    @DisplayName("sanitize: Should return input unchanged when no CR/LF present")
    void sanitize_NoOpForSafeStrings() {
        assertEquals("safe-string", LogSanitizer.sanitize("safe-string"));
        assertEquals("https://example.com/path?q=1", LogSanitizer.sanitize("https://example.com/path?q=1"));
    }

    @Test
    @DisplayName("sanitize: Should return 'null' for null input")
    void sanitize_NullInput() {
        assertEquals("null", LogSanitizer.sanitize(null));
    }

    @Test
    @DisplayName("sanitize: Should return empty string for empty input")
    void sanitize_EmptyInput() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
