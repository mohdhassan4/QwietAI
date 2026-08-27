package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

// Test fixture passwords below are not real credentials; they are deterministic inputs for hash verification
class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Salted hash format: salt:hash
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.verifyHashAsHex(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.verifyHashAsHex(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.sha256SaltedHex("password");
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.verifyHashAsHex(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123";
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword";
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and deterministic (HMAC-SHA256 based)")
    void lmHash_CaseInsensitiveAndDeterministic() {
        // Hash should be deterministic
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertEquals(hash1, hash2);

        // Hash should be case-insensitive
        assertEquals(hash1, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash1, PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Output should be 32 hex characters (16 bytes)
        assertEquals(32, hash1.length());
        assertTrue(hash1.matches("[0-9a-f]{32}"));
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
