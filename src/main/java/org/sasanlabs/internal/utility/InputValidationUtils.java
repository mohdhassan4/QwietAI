package org.sasanlabs.internal.utility;

import java.util.regex.Pattern;

/**
 * Utility class for validating user-controlled input references before they are used to access
 * data. Prevents insecure direct object reference attacks by ensuring references match expected
 * patterns and bounds.
 */
public final class InputValidationUtils {

    private static final int MAX_USERNAME_LENGTH = 64;
    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._@\\-]{1," + MAX_USERNAME_LENGTH + "}$");

    private static final int MAX_ID_VALUE = 1_000_000;

    private InputValidationUtils() {}

    /**
     * Validates that a username reference matches expected patterns (alphanumeric with limited
     * special characters) and is within a reasonable length.
     *
     * @param username the username to validate
     * @return true if the username is valid, false otherwise
     */
    public static boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username).matches();
    }

    /**
     * Validates that a numeric ID reference is a positive integer within reasonable bounds.
     *
     * @param id the numeric id to validate
     * @return true if the id is valid, false otherwise
     */
    public static boolean isValidId(int id) {
        return id > 0 && id <= MAX_ID_VALUE;
    }

    /**
     * Validates that a string ID reference can be parsed as a positive integer within reasonable
     * bounds.
     *
     * @param id the string id to validate
     * @return true if the id is a valid positive integer reference, false otherwise
     */
    public static boolean isValidId(String id) {
        if (id == null || id.isEmpty()) {
            return false;
        }
        try {
            int numericId = Integer.parseInt(id.trim());
            return isValidId(numericId);
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
