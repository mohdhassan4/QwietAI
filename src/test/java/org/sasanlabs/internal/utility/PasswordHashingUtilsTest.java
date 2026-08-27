package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash in saltHex:hashHex format")
    void md4Hash_SaltedFormat() {
        String result = PasswordHashingUtils.md4Hex("password123");
        // Format: saltHex:hashHex (salt is 16 bytes = 32 hex chars)
        assertTrue(result.contains(":"), "Should contain separator");
        String[] parts = result.split(":", 2);
        assertEquals(32, parts[0].length(), "Salt should be 32 hex chars (16 bytes)");
        assertTrue(parts[1].matches("[0-9a-f]+"), "Hash should be hex");
        // Verify the salted hash can be validated
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password123", result, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", result, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash in saltHex:hashHex format")
    void md5Hash_SaltedFormat() {
        String result = PasswordHashingUtils.md5Hex("password");
        assertTrue(result.contains(":"), "Should contain separator");
        String[] parts = result.split(":", 2);
        assertEquals(32, parts[0].length(), "Salt should be 32 hex chars (16 bytes)");
        // Verify with verifySaltedHash
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", result, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", result, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("MD5: Two hashes of the same password should differ due to random salt")
    void md5Hash_UniquePerCall() {
        String hash1 = PasswordHashingUtils.md5Hex("password");
        String hash2 = PasswordHashingUtils.md5Hex("password");
        assertNotEquals(hash1, hash2, "Random salt means hashes differ each call");
        // But both should verify
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", hash1, PasswordHashingUtils.HashAlgorithm.MD5));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", hash2, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256 with random salt: Should generate and verify correctly")
    void sha256HashWithRandomSalt_CorrectFormat() {
        String result = PasswordHashingUtils.sha256HexWithRandomSalt("password");
        assertTrue(result.contains(":"), "Should contain separator");
        String[] parts = result.split(":", 2);
        assertEquals(32, parts[0].length(), "Salt should be 32 hex chars (16 bytes)");
        assertEquals(64, parts[1].length(), "SHA-256 hash should be 64 hex chars");
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", result, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", result, PasswordHashingUtils.HashAlgorithm.SHA256));
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
    @DisplayName("LM Hash: Should be case-insensitive and deterministic")
    void lmHash_CaseInsensitiveAndDeterministic() {
        // LM hash converts password to uppercase, so all case variants produce the same hash
        // Not a secret: deterministic hash output used for test assertions only
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // All case variants must produce identical hashes (case-insensitive)
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Hash must be deterministic (same input always yields same output)
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Hash format: 32 hex characters (two 8-byte halves = 16 bytes = 32 hex chars)
        assertNotNull(hash1);
        assertEquals(32, hash1.length());
        assertTrue(hash1.matches("[0-9a-f]{32}"));

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
    @DisplayName("Hex Utility: Should convert hex strings back to byte arrays")
    void hexToBytes_Conversion() {
        String hex = "000f107fff";
        byte[] expected = {0, 15, 16, 127, -1};
        assertArrayEquals(expected, EncodingUtils.hexToBytes(hex));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
