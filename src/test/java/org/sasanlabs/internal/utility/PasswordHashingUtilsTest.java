package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");

        // Salted hashes should be different each time (unique salt)
        assertNotEquals(hash1, hash2);

        // Both should contain the salt:hash separator
        assertTrue(hash1.contains(":"));
        assertTrue(hash2.contains(":"));

        // Verification should succeed for correct password
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash1, PasswordHashingUtils.HashAlgorithm.MD4));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash2, PasswordHashingUtils.HashAlgorithm.MD4));

        // Verification should fail for wrong password
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash1, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String hash1 = PasswordHashingUtils.md5Hex("password");
        String hash2 = PasswordHashingUtils.md5Hex("password");

        // Salted hashes should be different each time
        assertNotEquals(hash1, hash2);
        assertTrue(hash1.contains(":"));

        // Verification should succeed
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash1, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash1, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.saltedSha256Hex("password");

        assertTrue(hash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // nosec: test fixture, not a real credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // nosec: test fixture, not a real credential
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
        // LM hash uppercases the password, so all case variants must produce the same result
        String hash = PasswordHashingUtils.lmHash("password");

        assertNotNull(hash);
        assertFalse(hash.isEmpty());
        assertEquals(hash, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash, PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Determinism: same input always produces same output
        assertEquals(hash, PasswordHashingUtils.lmHash("password"));
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

    @Test
    @DisplayName("verifyHash: Should handle null and malformed inputs safely")
    void verifyHash_NullAndMalformedInputs() {
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        null, "salt:hash", PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "password", null, PasswordHashingUtils.HashAlgorithm.SHA256));
        // Malformed stored hash (no separator)
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "password", "noseparator", PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("getHashAsHex: Should produce salt:hash format with 16-byte salt")
    void getHashAsHex_ProducesSaltedFormat() {
        String hash =
                PasswordHashingUtils.getHashAsHex(
                        "test", PasswordHashingUtils.HashAlgorithm.SHA256);
        String[] parts = hash.split(":", 2);
        assertEquals(2, parts.length);
        // 16 bytes = 32 hex chars for the salt
        assertEquals(32, parts[0].length());
        // SHA-256 digest = 64 hex chars
        assertEquals(64, parts[1].length());
    }
}
