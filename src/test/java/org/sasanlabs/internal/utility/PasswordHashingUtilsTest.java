package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a valid deterministic hex hash")
    void md4Hash_CorrectHex() {
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertNotNull(actual);
        assertEquals(32, actual.length(), "MD4 hash must be 32 hex characters");
        assertTrue(actual.matches("[0-9a-f]+"), "MD4 hash must be lowercase hex");
        assertEquals(actual, PasswordHashingUtils.md4Hex("password123"), "Must be deterministic");
        assertNotEquals(actual, PasswordHashingUtils.md4Hex("different_input"));
    }

    @Test
    @DisplayName("MD5: Should generate a valid deterministic hex hash")
    void md5Hash_CorrectHex() {
        String actual = PasswordHashingUtils.md5Hex("password");
        assertNotNull(actual);
        assertEquals(32, actual.length(), "MD5 hash must be 32 hex characters");
        assertTrue(actual.matches("[0-9a-f]+"), "MD5 hash must be lowercase hex");
        assertEquals(actual, PasswordHashingUtils.md5Hex("password"), "Must be deterministic");
        assertNotEquals(actual, PasswordHashingUtils.md5Hex("different_input"));
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a valid deterministic hex hash")
    void sha256Hash_CorrectHex() {
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertNotNull(actual);
        assertEquals(64, actual.length(), "SHA-256 hash must be 64 hex characters");
        assertTrue(actual.matches("[0-9a-f]+"), "SHA-256 hash must be lowercase hex");
        assertEquals(actual, PasswordHashingUtils.unsaltedSha256Hex("password"), "Must be deterministic");
        assertNotEquals(actual, PasswordHashingUtils.unsaltedSha256Hex("different_input"));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // Not a real credential - test fixture value
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Not a real credential - test fixture value
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and deterministic")
    void lmHash_LegacyStandards() {
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // Must be deterministic and case-insensitive
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Different passwords must produce different hashes
        assertNotEquals(hash1, PasswordHashingUtils.lmHash("different"));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
