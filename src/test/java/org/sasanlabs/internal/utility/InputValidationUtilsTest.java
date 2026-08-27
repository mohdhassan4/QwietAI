package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class InputValidationUtilsTest {

    @Test
    @DisplayName("Should reject null username")
    void rejectsNull() {
        assertFalse(InputValidationUtils.isValidUsername(null));
    }

    @Test
    @DisplayName("Should reject empty username")
    void rejectsEmpty() {
        assertFalse(InputValidationUtils.isValidUsername(""));
    }

    @Test
    @DisplayName("Should reject username exceeding 64 characters")
    void rejectsOverlyLong() {
        String longUsername = "a".repeat(65);
        assertFalse(InputValidationUtils.isValidUsername(longUsername));
    }

    @Test
    @DisplayName("Should accept username at exactly 64 characters")
    void acceptsMaxLength() {
        String maxUsername = "a".repeat(64);
        assertTrue(InputValidationUtils.isValidUsername(maxUsername));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "admin' OR '1'='1",
                "user<script>",
                "user;DROP TABLE",
                "user name",
                "user@domain",
                "../etc/passwd",
                "user\ttab",
                "user\nnewline"
            })
    @DisplayName("Should reject usernames with special characters")
    void rejectsSpecialCharacters(String username) {
        assertFalse(InputValidationUtils.isValidUsername(username));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "admin",
                "Alice",
                "user_name",
                "user-name",
                "admin123",
                "Charlie",
                "admin_sqli",
                "admin_logs",
                "user3"
            })
    @DisplayName("Should accept valid alphanumeric usernames with underscore and hyphen")
    void acceptsValidUsernames(String username) {
        assertTrue(InputValidationUtils.isValidUsername(username));
    }
}
