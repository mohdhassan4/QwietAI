package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash that can be verified")
    void md4Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Salted format: saltHex:hashHex
        assertTrue(hash.contains(":"), "Hash should be in salt:hash format");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash that can be verified")
    void md5Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Hash should be in salt:hash format");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash that can be verified")
    void sha256Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(hash.contains(":"), "Hash should be in salt:hash format");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("Salted hashes should be unique due to random salt")
    void saltedHashes_ShouldBeUnique() {
        String hash1 = PasswordHashingUtils.md5Hex("password");
        String hash2 = PasswordHashingUtils.md5Hex("password");
        assertNotEquals(hash1, hash2, "Each call should produce a unique salted hash");
        // But both should verify against the original password
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash1, PasswordHashingUtils.HashAlgorithm.MD5));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash2, PasswordHashingUtils.HashAlgorithm.MD5));
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
    @DisplayName("LM Hash: Should be deterministic and case-insensitive")
    void lmHash_DeterministicAndCaseInsensitive() {
        // LM hash uppercases the password, so all case variants produce the same result
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());

        // All case variants must produce the same hash (case-insensitive)
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Deterministic: same input always yields same output
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Different passwords produce different hashes
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
