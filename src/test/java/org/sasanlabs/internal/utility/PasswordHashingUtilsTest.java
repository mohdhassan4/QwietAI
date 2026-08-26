package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a deterministic salted hash")
    void md4Hash_Deterministic() {
        // With application salt, the hash is deterministic for the same input
        String first = PasswordHashingUtils.md4Hex("password123");
        String second = PasswordHashingUtils.md4Hex("password123");
        assertEquals(first, second, "Hash must be deterministic");
        assertNotNull(first);
        assertTrue(first.matches("[0-9a-f]+"), "Hash must be lowercase hex");
        // Different input produces different hash
        assertNotEquals(first, PasswordHashingUtils.md4Hex("other"));
    }

    @Test
    @DisplayName("MD5: Should generate a deterministic salted hash")
    void md5Hash_Deterministic() {
        // With application salt, the hash is deterministic for the same input
        String first = PasswordHashingUtils.md5Hex("password");
        String second = PasswordHashingUtils.md5Hex("password");
        assertEquals(first, second, "Hash must be deterministic");
        assertNotNull(first);
        assertTrue(first.matches("[0-9a-f]+"), "Hash must be lowercase hex");
        // Different input produces different hash
        assertNotEquals(first, PasswordHashingUtils.md5Hex("other"));
    }

    @Test
    @DisplayName("SHA-256: Should generate a deterministic salted hash")
    void sha256Hash_Deterministic() {
        // With application salt, the hash is deterministic for the same input
        String first = PasswordHashingUtils.unsaltedSha256Hex("password");
        String second = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(first, second, "Hash must be deterministic");
        assertNotNull(first);
        assertTrue(first.matches("[0-9a-f]+"), "Hash must be lowercase hex");
        // Different input produces different hash
        assertNotEquals(first, PasswordHashingUtils.unsaltedSha256Hex("other"));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // Test fixture, not a real credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Test fixture, not a real credential
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
        // Verify determinism: same input always produces the same hash — output is not a secret
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertEquals(hash1, hash2, "LM hash must be deterministic");

        // Verify case-insensitivity: different cases produce same hash
        assertEquals(hash1, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash1, PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Verify the hash is a non-empty hex string
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertTrue(hash1.matches("[0-9a-f]+"), "Hash must be lowercase hex");

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
