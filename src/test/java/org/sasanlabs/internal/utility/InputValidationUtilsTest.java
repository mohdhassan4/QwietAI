package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class InputValidationUtilsTest {

    @Test
    @DisplayName("validateUsername: Should accept valid alphanumeric username")
    void validateUsername_ValidAlphanumeric() {
        assertEquals("admin", InputValidationUtils.validateUsername("admin"));
    }

    @Test
    @DisplayName("validateUsername: Should accept username with allowed special characters")
    void validateUsername_ValidWithSpecialChars() {
        assertEquals("user_name", InputValidationUtils.validateUsername("user_name"));
        assertEquals("user-name", InputValidationUtils.validateUsername("user-name"));
        assertEquals("user.name", InputValidationUtils.validateUsername("user.name"));
        assertEquals("user@email.com", InputValidationUtils.validateUsername("user@email.com"));
    }

    @Test
    @DisplayName("validateUsername: Should trim whitespace from valid username")
    void validateUsername_TrimsWhitespace() {
        assertEquals("admin", InputValidationUtils.validateUsername("  admin  "));
    }

    @Test
    @DisplayName("validateUsername: Should reject null username")
    void validateUsername_RejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> InputValidationUtils.validateUsername(null));
    }

    @Test
    @DisplayName("validateUsername: Should reject empty username")
    void validateUsername_RejectsEmpty() {
        assertThrows(IllegalArgumentException.class, () -> InputValidationUtils.validateUsername(""));
        assertThrows(
                IllegalArgumentException.class, () -> InputValidationUtils.validateUsername("   "));
    }

    @Test
    @DisplayName("validateUsername: Should reject username with SQL injection characters")
    void validateUsername_RejectsSqlInjection() {
        assertThrows(
                IllegalArgumentException.class,
                () -> InputValidationUtils.validateUsername("admin' OR '1'='1"));
    }

    @Test
    @DisplayName("validateUsername: Should reject username exceeding max length")
    void validateUsername_RejectsOverlyLong() {
        String longUsername = "a".repeat(65);
        assertThrows(
                IllegalArgumentException.class,
                () -> InputValidationUtils.validateUsername(longUsername));
    }

    @Test
    @DisplayName("validateUsername: Should accept username at max length")
    void validateUsername_AcceptsMaxLength() {
        String maxUsername = "a".repeat(64);
        assertEquals(maxUsername, InputValidationUtils.validateUsername(maxUsername));
    }

    @Test
    @DisplayName("validatePositiveId: Should accept positive integer")
    void validatePositiveId_AcceptsPositive() {
        assertEquals(1, InputValidationUtils.validatePositiveId(1));
        assertEquals(42, InputValidationUtils.validatePositiveId(42));
        assertEquals(Integer.MAX_VALUE, InputValidationUtils.validatePositiveId(Integer.MAX_VALUE));
    }

    @Test
    @DisplayName("validatePositiveId: Should reject zero")
    void validatePositiveId_RejectsZero() {
        assertThrows(
                IllegalArgumentException.class, () -> InputValidationUtils.validatePositiveId(0));
    }

    @Test
    @DisplayName("validatePositiveId: Should reject negative integer")
    void validatePositiveId_RejectsNegative() {
        assertThrows(
                IllegalArgumentException.class, () -> InputValidationUtils.validatePositiveId(-1));
        assertThrows(
                IllegalArgumentException.class,
                () -> InputValidationUtils.validatePositiveId(Integer.MIN_VALUE));
    }
}
