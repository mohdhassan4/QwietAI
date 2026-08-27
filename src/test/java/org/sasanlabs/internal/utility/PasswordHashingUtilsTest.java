package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123";
        String hash = PasswordHashingUtils.md4Hex(password);

        // Salted hashes contain separator
        assertTrue(hash.contains(":"), "Salted hash must contain ':' separator");

        // Same password hashed twice produces different outputs (random salt)
        String hash2 = PasswordHashingUtils.md4Hex(password);
        assertNotEquals(hash, hash2, "Two salted hashes of same password must differ");

        // Verification works
        assertTrue(PasswordHashingUtils.isValidMd4(password, hash));
        assertTrue(PasswordHashingUtils.isValidMd4(password, hash2));
        assertFalse(PasswordHashingUtils.isValidMd4("wrongPassword", hash));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password";
        String hash = PasswordHashingUtils.md5Hex(password);

        // Salted hashes contain separator
        assertTrue(hash.contains(":"), "Salted hash must contain ':' separator");

        // Same password hashed twice produces different outputs (random salt)
        String hash2 = PasswordHashingUtils.md5Hex(password);
        assertNotEquals(hash, hash2, "Two salted hashes of same password must differ");

        // Verification works
        assertTrue(PasswordHashingUtils.isValidMd5(password, hash));
        assertTrue(PasswordHashingUtils.isValidMd5(password, hash2));
        assertFalse(PasswordHashingUtils.isValidMd5("wrongPassword", hash));
    }

    @Test
    @DisplayName("SHA-1: Should generate a salted hash and verify correctly")
    void sha1Hash_SaltedAndVerifiable() {
        String password = "testpass";
        String hash = PasswordHashingUtils.sha1Hex(password);

        assertTrue(hash.contains(":"), "Salted hash must contain ':' separator");

        String hash2 = PasswordHashingUtils.sha1Hex(password);
        assertNotEquals(hash, hash2, "Two salted hashes of same password must differ");

        assertTrue(PasswordHashingUtils.isValidSha1(password, hash));
        assertFalse(PasswordHashingUtils.isValidSha1("wrongPassword", hash));
    }

    @Test
    @DisplayName("SHA-256 (single-param): Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String password = "securePass456";
        String hash = PasswordHashingUtils.sha256Hex(password);

        assertTrue(hash.contains(":"), "Salted hash must contain ':' separator");

        String hash2 = PasswordHashingUtils.sha256Hex(password);
        assertNotEquals(hash, hash2, "Two salted hashes of same password must differ");

        assertTrue(PasswordHashingUtils.isValidSha256(password, hash));
        assertFalse(PasswordHashingUtils.isValidSha256("wrongPassword", hash));
    }

    @Test
    @DisplayName("SHA-256 with explicit string salt: Should correctly validate salted hashes")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // Not a secret: test fixture constant
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Not a secret: test fixture constant
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
        // LM hash uses AES-256/GCM internally; verify determinism and case-insensitivity
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // All case variants must produce the same hash (LM uppercases input)
        assertEquals(hash1, hash2);
        assertEquals(hash2, hash3);

        // Hash must be deterministic (same input, same output)
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Hash must not be empty
        assertFalse(hash1.isEmpty());

        // Different passwords must produce different hashes
        String differentHash = PasswordHashingUtils.lmHash("different");
        assertNotEquals(hash1, differentHash);
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Hex Utility: hexToBytes should be inverse of bytesToHex")
    void hexToBytes_RoundTrip() {
        byte[] original = {0, 15, 16, 127, -1, 64, 32};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] decoded = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, decoded);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(
                PasswordHashingUtils.isValidHash(
                        null, "abc:def", PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.isValidHash(
                        "somePass", null, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("isValidHash: Should reject malformed stored hash (no separator)")
    void isValidHash_RejectsMalformed() {
        assertFalse(
                PasswordHashingUtils.isValidHash(
                        "password",
                        "noseparatorhere",
                        PasswordHashingUtils.HashAlgorithm.MD5));
    }
}
