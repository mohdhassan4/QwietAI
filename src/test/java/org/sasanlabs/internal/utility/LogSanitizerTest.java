package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        String input = "http://evil.com\r\nINFO Fake log entry";
        String result = LogSanitizer.sanitize(input);
        assertEquals("http://evil.com__INFO Fake log entry", result);
        assertFalse(result.contains("\r"));
        assertFalse(result.contains("\n"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        String input = "value\rwith\rCR";
        String result = LogSanitizer.sanitize(input);
        assertEquals("value_with_CR", result);
    }

    @Test
    void sanitize_removesLineFeed() {
        String input = "value\nwith\nLF";
        String result = LogSanitizer.sanitize(input);
        assertEquals("value_with_LF", result);
    }

    @Test
    void sanitize_removesTab() {
        String input = "value\twith\ttab";
        String result = LogSanitizer.sanitize(input);
        assertEquals("value_with_tab", result);
    }

    @Test
    void sanitize_preservesNormalCharacters() {
        String input = "https://example.com/path?q=hello&x=1";
        String result = LogSanitizer.sanitize(input);
        assertEquals(input, result);
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
    void sanitize_removesNullByteAndDEL() {
        // Use char construction for control chars that are hard to express as literals
        String input = "value" + (char) 0 + "with" + (char) 127 + "ctrl";
        String result = LogSanitizer.sanitize(input);
        assertEquals("value_with_ctrl", result);
    }
}
