package org.sasanlabs.internal.utility;

import java.util.regex.Pattern;

/**
 * Utility class for validating user-controlled input before it is used in database lookups or other
 * sensitive operations, preventing Insecure Direct Object Reference (IDOR) attacks.
 *
 * @author security-remediation
 */
public final class InputValidationUtils {

    private InputValidationUtils() {}

    /** Maximum allowed username length. */
    private static final int MAX_USERNAME_LENGTH = 64;

    /** Allowed username pattern: alphanumeric, underscore, hyphen, dot, and @ (for emails). */
    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_@.\\-]{1," + MAX_USERNAME_LENGTH + "}$");

    /**
     * Validates that a username conforms to the expected format. Usernames must be 1-64 characters,
     * consisting of alphanumeric characters, underscores, hyphens, dots, or @ symbols.
     *
     * @param username the username to validate
     * @return the validated username (trimmed)
     * @throws IllegalArgumentException if the username is null, empty, or contains invalid
     *     characters
     */
    public static String validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username must not be null or empty");
        }
        String trimmed = username.trim();
        if (!USERNAME_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException(
                    "Username contains invalid characters or exceeds maximum length");
        }
        return trimmed;
    }

    /**
     * Validates that an ID is a positive integer suitable for database lookup.
     *
     * @param id the id to validate
     * @return the validated id
     * @throws IllegalArgumentException if the id is not positive
     */
    public static int validatePositiveId(int id) {
        if (id <= 0) {
            throw new IllegalArgumentException("ID must be a positive integer");
        }
        return id;
    }
}
