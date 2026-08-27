package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash in hexSalt:hexHash format")
    void md4Hash_SaltedFormat() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Must contain separator
        assertTrue(hash.contains(":"), "Salted hash must contain separator");
        String[] parts = hash.split(":", 2);
        assertEquals(32, parts[0].length(), "Salt should be 16 bytes (32 hex chars)");
        assertTrue(parts[0].matches("[0-9a-f]+"), "Salt should be lowercase hex");
        assertTrue(parts[1].matches("[0-9a-f]+"), "Hash should be lowercase hex");
    }

    @Test
    @DisplayName("MD4: Should produce different hashes due to random salt")
    void md4Hash_RandomSalt() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2, "Each call should use a different random salt");
    }

    @Test
    @DisplayName("MD4: Should verify correctly with verifyHash")
    void md4Hash_VerifyRoundTrip() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrongPassword", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Salted hash must contain separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(hash.contains(":"), "Salted hash must contain separator");
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
        String rawPassword = "securePassword123"; // Not a real credential - test fixture
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Not a real credential - test fixture
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and deterministic with AES-128")
    void lmHash_CaseInsensitiveAndDeterministic() {
        // LM hash converts input to uppercase, so all case variants must match
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertEquals(hash1, hash2, "LM hash must be case-insensitive");
        assertEquals(hash1, hash3, "LM hash must be case-insensitive");

        // Determinism: same input always produces the same hash
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // AES-128 produces 16 bytes per half (two halves concatenated = 32 bytes = 64 hex chars)
        assertEquals(64, hash1.length(), "AES-128 based LM hash should be 64 hex characters");

        // Output is valid lowercase hex
        assertTrue(hash1.matches("[0-9a-f]+"), "Hash should be lowercase hex");

        // Different passwords produce different hashes
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
    @DisplayName("Hex Utility: hexToBytes should round-trip with bytesToHex")
    void hexToBytes_RoundTrip() {
        byte[] original = {0, 15, 16, 127, -1, 42};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] recovered = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, recovered);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }

    @Test
    @DisplayName("verifyHash: Should reject null inputs gracefully")
    void verifyHash_NullInputs() {
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        null, "abc:def", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "pass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("verifyHash: Should reject stored hash without separator")
    void verifyHash_NoSeparator() {
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "pass", "abcdef1234567890", PasswordHashingUtils.HashAlgorithm.MD5));
    }
}
