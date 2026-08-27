package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_nullInput_returnsNullMarker() {
        assertEquals("(null)", LogSanitizer.sanitize(null));
    }

    @Test
    void sanitize_emptyString_returnsEmpty() {
        assertEquals("", LogSanitizer.sanitize(""));
    }

    @Test
    void sanitize_cleanInput_returnsUnchanged() {
        String clean = "https://example.com/path?query=value";
        assertEquals(clean, LogSanitizer.sanitize(clean));
    }

    @Test
    void sanitize_newlineCharacters_replacedWithUnderscore() {
        String malicious = "legit\r\nINFO  Fake log entry";
        String result = LogSanitizer.sanitize(malicious);
        assertFalse(result.contains("\r"));
        assertFalse(result.contains("\n"));
        assertEquals("legit__INFO  Fake log entry", result);
    }

    @Test
    void sanitize_carriageReturnOnly_replacedWithUnderscore() {
        String input = "value\rwith CR";
        String result = LogSanitizer.sanitize(input);
        assertFalse(result.contains("\r"));
        assertEquals("value_with CR", result);
    }

    @Test
    void sanitize_lineFeedOnly_replacedWithUnderscore() {
        String input = "value\nwith LF";
        String result = LogSanitizer.sanitize(input);
        assertFalse(result.contains("\n"));
        assertEquals("value_with LF", result);
    }

    @Test
    void sanitize_controlCharacters_replacedWithUnderscore() {
        // Build string with control characters via char concatenation
        String input = "prefix" + (char) 0x00 + (char) 0x01 + (char) 0x1f + "suffix";
        String result = LogSanitizer.sanitize(input);
        assertEquals("prefix___suffix", result);
    }

    @Test
    void sanitize_tabIsPreserved() {
        String input = "col1\tcol2";
        assertEquals("col1\tcol2", LogSanitizer.sanitize(input));
    }

    @Test
    void sanitize_multipleInjectionAttempts_allNeutralized() {
        String input = "line1\nline2\r\nline3\rline4";
        String result = LogSanitizer.sanitize(input);
        assertFalse(result.contains("\n"));
        assertFalse(result.contains("\r"));
        assertEquals("line1_line2__line3_line4", result);
    }
}
