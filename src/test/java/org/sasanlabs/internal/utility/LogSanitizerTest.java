package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitizesNewlineCharacters() {
        assertEquals("first_second", LogSanitizer.sanitize("first\nsecond"));
        assertEquals("first_second", LogSanitizer.sanitize("first\rsecond"));
        assertEquals("first__second", LogSanitizer.sanitize("first\r\nsecond"));
    }

    @Test
    void sanitizesTabCharacters() {
        assertEquals("first_second", LogSanitizer.sanitize("first\tsecond"));
    }

    @Test
    void returnsEmptyStringForNull() {
        assertEquals("", LogSanitizer.sanitize(null));
    }

    @Test
    void returnsSameStringWhenNoControlCharacters() {
        String clean = "https://example.com/path?q=value";
        assertEquals(clean, LogSanitizer.sanitize(clean));
    }

    @Test
    void handlesEmptyString() {
        assertEquals("", LogSanitizer.sanitize(""));
    }
}
