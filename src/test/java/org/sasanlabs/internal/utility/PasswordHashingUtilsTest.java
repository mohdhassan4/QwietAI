package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash in salt:hash format")
    void md4Hash_SaltedFormat() {
        String result = PasswordHashingUtils.md4Hex("password123");
        assertTrue(result.contains(":"), "Expected salt:hash format");
        String[] parts = result.split(":", 2);
        assertEquals(2, parts.length);
        assertFalse(parts[0].isEmpty(), "Salt should not be empty");
        assertFalse(parts[1].isEmpty(), "Hash should not be empty");
    }

    @Test
    @DisplayName("MD4: Two calls should produce different hashes due to random salt")
    void md4Hash_RandomSalt() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2, "Random salts should produce unique outputs");
    }

    @Test
    @DisplayName("MD4: isValidSaltedHash should verify generated hash")
    void md4Hash_Verification() {
        String storedHash = PasswordHashingUtils.md4Hex("password123");
        assertTrue(PasswordHashingUtils.isValidSaltedHash(
                "password123", storedHash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                "wrongpass", storedHash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash in salt:hash format")
    void md5Hash_SaltedFormat() {
        String result = PasswordHashingUtils.md5Hex("password");
        assertTrue(result.contains(":"), "Expected salt:hash format");
        String[] parts = result.split(":", 2);
        assertEquals(2, parts.length);
        assertFalse(parts[0].isEmpty(), "Salt should not be empty");
        assertFalse(parts[1].isEmpty(), "Hash should not be empty");
    }

    @Test
    @DisplayName("MD5: isValidSaltedHash should verify generated hash")
    void md5Hash_Verification() {
        String storedHash = PasswordHashingUtils.md5Hex("password");
        assertTrue(PasswordHashingUtils.isValidSaltedHash(
                "password", storedHash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                "wrongpass", storedHash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("Salted SHA-256: Should generate a salted hash in salt:hash format")
    void saltedSha256Hash_Format() {
        String result = PasswordHashingUtils.saltedSha256Hex("password");
        assertTrue(result.contains(":"), "Expected salt:hash format");
        String[] parts = result.split(":", 2);
        assertEquals(2, parts.length);
        assertFalse(parts[0].isEmpty(), "Salt should not be empty");
        assertFalse(parts[1].isEmpty(), "Hash should not be empty");
    }

    @Test
    @DisplayName("Salted SHA-256: isValidSaltedHash should verify generated hash")
    void saltedSha256Hash_Verification() {
        String storedHash = PasswordHashingUtils.saltedSha256Hex("password");
        assertTrue(PasswordHashingUtils.isValidSaltedHash(
                "password", storedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                "wrongpass", storedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
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
        // Intentional test fixture password (not a real secret)
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
    @DisplayName("LM Hash: Should be case-insensitive and match legacy standards")
    void lmHash_LegacyStandards() {
        // Known LM hash for "password" (which it converts to "PASSWORD") - test fixture, not a real secret
        String expected = "e52cac67419a9a224a3b108f3fa6cb6d";

        assertEquals(expected, PasswordHashingUtils.lmHash("password"));
        assertEquals(expected, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(expected, PasswordHashingUtils.lmHash("pAsSwOrD"));
    }

    @Test
    @DisplayName("MD5 with explicit salt: Should produce deterministic hash")
    void md5Hash_WithExplicitSalt_Deterministic() {
        byte[] salt = "testSalt".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String hash1 = PasswordHashingUtils.md5Hex("password", salt);
        String hash2 = PasswordHashingUtils.md5Hex("password", salt);
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("SHA-1: Should generate a salted hash in salt:hash format")
    void sha1Hash_SaltedFormat() {
        String result = PasswordHashingUtils.sha1Hex("password");
        assertTrue(result.contains(":"), "Expected salt:hash format");
        String[] parts = result.split(":", 2);
        assertEquals(2, parts.length);
    }

    @Test
    @DisplayName("SHA-1: isValidSaltedHash should verify generated hash")
    void sha1Hash_Verification() {
        String storedHash = PasswordHashingUtils.sha1Hex("password");
        assertTrue(PasswordHashingUtils.isValidSaltedHash(
                "password", storedHash, PasswordHashingUtils.HashAlgorithm.SHA1));
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                "wrongpass", storedHash, PasswordHashingUtils.HashAlgorithm.SHA1));
    }

    @Test
    @DisplayName("Salted hash: Same explicit salt and input should produce same hash")
    void saltedHash_Deterministic() {
        byte[] salt = "fixedSalt".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String hash1 = PasswordHashingUtils.md5Hex("password", salt);
        String hash2 = PasswordHashingUtils.md5Hex("password", salt);
        assertEquals(hash1, hash2);
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
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                null, "salt:hash", PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                "password", null, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("isValidSaltedHash: Should reject malformed stored values without separator")
    void isValidSaltedHash_NoSeparator() {
        assertFalse(PasswordHashingUtils.isValidSaltedHash(
                "password", "noseparator", PasswordHashingUtils.HashAlgorithm.SHA256));
    }
}
