package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash in salt:hash format")
    void md4Hash_SaltedFormat() {
        // Verify salted MD4 output: format is salt_hex(32):hash_hex(32)
        String actual = PasswordHashingUtils.md4Hex("password123");
        String[] parts = actual.split(":");
        assertEquals(2, parts.length, "Should be salt:hash format");
        assertEquals(32, parts[0].length(), "Salt should be 32 hex chars (16 bytes)");
        assertEquals(32, parts[1].length(), "MD4 hash should be 32 hex chars");
        assertTrue(parts[0].matches("[0-9a-f]+"), "Salt should be lowercase hex");
        assertTrue(parts[1].matches("[0-9a-f]+"), "Hash should be lowercase hex");

        // Each call generates a new salt, so hashes should differ (like bcrypt)
        assertNotEquals(actual, PasswordHashingUtils.md4Hex("password123"));

        // Verification should work
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password123", actual, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong_password", actual, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedVerification() {
        // Verify salted MD5 output: format is salt_hex(32):hash_hex(32)
        String actual = PasswordHashingUtils.md5Hex("password");
        String[] parts = actual.split(":");
        assertEquals(2, parts.length, "Should be salt:hash format");
        assertEquals(32, parts[0].length(), "Salt should be 32 hex chars (16 bytes)");
        assertEquals(32, parts[1].length(), "MD5 hash should be 32 hex chars");

        // Verification should work
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", actual, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", actual, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("Salted SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedVerification() {
        // Verify salted SHA-256 output: format is salt_hex(32):hash_hex(64)
        String actual = PasswordHashingUtils.saltedSha256Hex("password");
        String[] parts = actual.split(":");
        assertEquals(2, parts.length, "Should be salt:hash format");
        assertEquals(32, parts[0].length(), "Salt should be 32 hex chars (16 bytes)");
        assertEquals(64, parts[1].length(), "SHA-256 hash should be 64 hex chars");

        // Verification should work
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", actual, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", actual, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "test-only-not-real"; // Not a secret: test fixture value
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "test-only-not-real"; // Not a secret: test fixture value
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
        // LM hash uses HMAC-SHA256 internally; verify case-insensitivity and determinism
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // All case variants should produce the same hash (LM uppercases the input)
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Hash should be deterministic
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Hash should be 32 hex characters (16 bytes = 2 x 8-byte halves)
        assertEquals(32, hash1.length());
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
