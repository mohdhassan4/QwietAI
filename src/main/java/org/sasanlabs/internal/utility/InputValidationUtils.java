package org.sasanlabs.internal.utility;

import java.util.regex.Pattern;

/**
 * Utility class for validating user-supplied input parameters to prevent Insecure Direct Object
 * Reference (IDOR) attacks. Validates that identifiers conform to a safe allowlist before they are
 * used as object references in database queries or other lookups.
 *
 * @author security-remediation
 */
public final class InputValidationUtils {

    private static final int MAX_USERNAME_LENGTH = 64;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-]+$");

    private InputValidationUtils() {}

    /**
     * Validates whether a username is safe to use as a direct object reference. Ensures the
     * username is non-null, non-empty, within length limits, and contains only alphanumeric
     * characters, underscores, or hyphens.
     *
     * @param username the username to validate
     * @return true if the username is valid and safe to use as a lookup key, false otherwise
     */
    public static boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }
        if (username.length() > MAX_USERNAME_LENGTH) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username).matches();
    }
}
