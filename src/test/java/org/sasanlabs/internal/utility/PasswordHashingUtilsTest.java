package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123";
        String saltedHash = PasswordHashingUtils.md4Hex(password);

        // Should contain separator (salt:hash format)
        assertTrue(saltedHash.contains(":"));

        // Should verify correctly
        assertTrue(
                PasswordHashingUtils.verifyHashAsHex(
                        password, saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));

        // Two hashes of same password should differ (different random salts)
        String saltedHash2 = PasswordHashingUtils.md4Hex(password);
        assertNotEquals(saltedHash, saltedHash2);
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.md5Hex(password);

        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHashAsHex(
                        password, saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256 with explicit salt: Should compute deterministic hash")
    void sha256Hex_WithExplicitSalt() {
        String salt = "random_salt";
        String password = "securePassword123";
        // Same salt + password should produce same hash
        String hash1 = PasswordHashingUtils.sha256Hex(salt, password);
        String hash2 = PasswordHashingUtils.sha256Hex(salt, password);
        assertEquals(hash1, hash2);

        // Different salt should produce different hash
        String hash3 = PasswordHashingUtils.sha256Hex("other_salt", password);
        assertNotEquals(hash1, hash3);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123";
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
    @DisplayName("LM Hash: Should produce non-empty output with random IV prepended")
    void lmHash_LegacyStandards() {
        // After migration to AES with random IV, each call produces a unique result
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        // With random IV prepended, outputs are unique per call even for same key material
        // (IV is 16 bytes = 32 hex chars per half, total output is longer than before)
        assertNotNull(hash2);
        assertNotNull(hash3);
        // Each invocation with random IV produces a different hash
        assertNotEquals(hash1, hash2);
        // Output length should be consistent (2 halves, each: 16-byte IV + 16-byte ciphertext = 64 hex chars each)
        assertEquals(hash1.length(), hash2.length());
        assertEquals(hash1.length(), hash3.length());
        // Different passwords also produce different hashes
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
    @DisplayName("Hex Utility: hexToBytes should roundtrip with bytesToHex")
    void hexToBytes_Roundtrip() {
        byte[] original = {0, 15, 16, 127, -1};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] recovered = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, recovered);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        null, "abc:def", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHashAsHex(
                        "pass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("getHashAsHex with explicit salt: Should be deterministic")
    void getHashAsHex_ExplicitSalt_Deterministic() {
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        String hash1 =
                PasswordHashingUtils.getHashAsHex(
                        "test", PasswordHashingUtils.HashAlgorithm.SHA256, salt);
        String hash2 =
                PasswordHashingUtils.getHashAsHex(
                        "test", PasswordHashingUtils.HashAlgorithm.SHA256, salt);
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should now produce salted output and verify")
    void unsaltedSha256Hex_NowSalted() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.unsaltedSha256Hex(password);

        // Should be in salt:hash format
        assertTrue(saltedHash.contains(":"));

        // Should verify
        assertTrue(
                PasswordHashingUtils.verifyHashAsHex(
                        password, saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }
}
