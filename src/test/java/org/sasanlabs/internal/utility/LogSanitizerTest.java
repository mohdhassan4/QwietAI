package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

    @Test
    void sanitize_removesNewlines() {
        assertEquals("admin_injected", LogSanitizer.sanitize("admin\ninjected"));
    }

    @Test
    void sanitize_removesCarriageReturn() {
        assertEquals("admin_injected", LogSanitizer.sanitize("admin\rinjected"));
    }

    @Test
    void sanitize_removesCRLF() {
        assertEquals("admin__injected", LogSanitizer.sanitize("admin\r\ninjected"));
    }

    @Test
    void sanitize_removesTabs() {
        assertEquals("admin_injected", LogSanitizer.sanitize("admin\tinjected"));
    }

    @Test
    void sanitize_preservesNormalText() {
        assertEquals("normalUser", LogSanitizer.sanitize("normalUser"));
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
    void sanitize_multipleControlChars() {
        assertEquals(
                "fake_log_entry_INFO_admin_logged_in",
                LogSanitizer.sanitize("fake\nlog\nentry\nINFO\nadmin\nlogged\nin"));
    }
}
