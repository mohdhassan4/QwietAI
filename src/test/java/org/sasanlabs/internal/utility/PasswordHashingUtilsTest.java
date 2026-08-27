package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a deterministic salted hash")
    void md4Hash_CorrectHex() {
        // With application-level salt, hash is deterministic for same input
        String actual1 = PasswordHashingUtils.md4Hex("password123");
        String actual2 = PasswordHashingUtils.md4Hex("password123");
        assertEquals(actual1, actual2);
        assertEquals(32, actual1.length());
        assertTrue(actual1.matches("[0-9a-f]+"));
        // Different input produces different hash
        assertNotEquals(actual1, PasswordHashingUtils.md4Hex("differentPassword"));
    }

    @Test
    @DisplayName("MD5: Should generate a deterministic salted hash")
    void md5Hash_CorrectHex() {
        // With application-level salt, hash is deterministic for same input
        String actual1 = PasswordHashingUtils.md5Hex("password");
        String actual2 = PasswordHashingUtils.md5Hex("password");
        assertEquals(actual1, actual2);
        assertEquals(32, actual1.length());
        assertTrue(actual1.matches("[0-9a-f]+"));
        // Different input produces different hash
        assertNotEquals(actual1, PasswordHashingUtils.md5Hex("differentPassword"));
    }

    @Test
    @DisplayName("SHA-256: Should generate a deterministic salted hash")
    void sha256Hash_CorrectHex() {
        // With application-level salt, hash is deterministic for same input
        String actual1 = PasswordHashingUtils.unsaltedSha256Hex("password");
        String actual2 = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(actual1, actual2);
        assertEquals(64, actual1.length());
        assertTrue(actual1.matches("[0-9a-f]+"));
        // Different input produces different hash
        assertNotEquals(actual1, PasswordHashingUtils.unsaltedSha256Hex("differentPassword"));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // test fixture — not a real credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // test fixture — not a real credential
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be deterministic and case-insensitive")
    void lmHash_DeterministicAndCaseInsensitive() {
        // Hash must be deterministic — test fixture input, not a real credential
        String hash1 = PasswordHashingUtils.lmHash("password"); // test vector input (not a secret)
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertEquals(hash1, hash2);

        // LM hash is case-insensitive (input is uppercased internally)
        assertEquals(hash1, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash1, PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Hash must be a non-empty hex string
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertTrue(hash1.matches("[0-9a-f]+"));
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
