package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Salted hashes contain a separator between salt and hash
        assertTrue(hash.contains(":"), "Salted hash must contain separator");
        // Verification should succeed for the correct password
        assertTrue(
                PasswordHashingUtils.verifiesHash(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        // Verification should fail for wrong password
        assertFalse(
                PasswordHashingUtils.verifiesHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of the same password should differ due to random salt")
    void md4Hash_DifferentSaltsProduceDifferentHashes() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2, "Random salts must produce different hashes");
        // Both should still verify
        assertTrue(
                PasswordHashingUtils.verifiesHash(
                        "password123", hash1, PasswordHashingUtils.HashAlgorithm.MD4));
        assertTrue(
                PasswordHashingUtils.verifiesHash(
                        "password123", hash2, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Salted hash must contain separator");
        assertTrue(
                PasswordHashingUtils.verifiesHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifiesHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(hash.contains(":"), "Salted hash must contain separator");
        assertTrue(
                PasswordHashingUtils.verifiesHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifiesHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
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
        // Hash must be deterministic: same input produces same output
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertEquals(hash1, hash2, "Hash must be deterministic");

        // Hash must be case-insensitive
        assertEquals(
                PasswordHashingUtils.lmHash("password"),
                PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(
                PasswordHashingUtils.lmHash("password"),
                PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Different passwords must produce different hashes
        assertNotEquals(
                PasswordHashingUtils.lmHash("password"),
                PasswordHashingUtils.lmHash("different"));

        // Output should be 32 hex characters (128 bits)
        assertEquals(32, hash1.length());
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
        byte[] original = {0, 15, 16, 127, -1, 42};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] decoded = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, decoded);
    }

    @Test
    @DisplayName("verifiesHash: Should handle null inputs gracefully")
    void verifiesHash_NullInputs() {
        assertFalse(
                PasswordHashingUtils.verifiesHash(
                        null, "ab:cd", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifiesHash(
                        "pass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("verifiesHash: Should reject malformed stored hash without separator")
    void verifiesHash_MalformedHash() {
        assertFalse(
                PasswordHashingUtils.verifiesHash(
                        "pass", "noseparator", PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
