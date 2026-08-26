package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Salted format: hexSalt:hexHash
        assertTrue(hash.contains(":"), "Hash should contain salt separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of same input should differ due to random salt")
    void md4Hash_UniquePerCall() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2, "Each hash should use a unique random salt");
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Hash should contain salt separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-1: Should generate a salted hash and verify correctly")
    void sha1Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.sha1Hex("password");
        assertTrue(hash.contains(":"), "Hash should contain salt separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA1));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.SHA1));
    }

    @Test
    @DisplayName("SHA-256 salted: Should generate a salted hash and verify correctly")
    void saltedSha256Hash_Verifiable() {
        String hash = PasswordHashingUtils.saltedSha256Hex("password");
        assertTrue(hash.contains(":"), "Hash should contain salt separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
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
    @DisplayName("LM Hash (PBKDF2): Should use random salt and verify correctly (case-insensitive)")
    void lmHash_Pbkdf2SaltedAndVerifiable() {
        // Each call produces a different hash due to random salt
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertNotEquals(hash1, hash2, "Each hash should use a unique random salt");

        // Salted format: hexSalt:hexHash
        assertTrue(hash1.contains(":"), "Hash should contain salt separator");

        // Verification works for correct password
        assertTrue(PasswordHashingUtils.verifyLmHash("password", hash1));
        assertTrue(PasswordHashingUtils.verifyLmHash("password", hash2));

        // Case insensitivity is preserved (input is upper-cased internally)
        assertTrue(PasswordHashingUtils.verifyLmHash("PASSWORD", hash1));
        assertTrue(PasswordHashingUtils.verifyLmHash("pAsSwOrD", hash1));

        // Wrong password should not verify
        assertFalse(PasswordHashingUtils.verifyLmHash("different", hash1));

        // Null checks
        assertFalse(PasswordHashingUtils.verifyLmHash(null, hash1));
        assertFalse(PasswordHashingUtils.verifyLmHash("password", null));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Hex Utility: hexToBytes should round-trip with bytesToHex")
    void hexToBytes_RoundTrip() {
        byte[] original = {0, 15, 16, 127, -1};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] restored = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, restored);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        null, "abc:def", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "somePass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }
}
