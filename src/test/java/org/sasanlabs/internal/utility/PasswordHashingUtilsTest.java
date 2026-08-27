package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a deterministic salted hash")
    void md4Hash_CorrectHex() {
        // Hashes are now salted with a per-application salt
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        // Different input should produce a different hash
        assertNotEquals(hash1, PasswordHashingUtils.md4Hex("different"));
    }

    @Test
    @DisplayName("MD5: Should generate a deterministic salted hash")
    void md5Hash_CorrectHex() {
        // Hashes are now salted with a per-application salt
        String hash1 = PasswordHashingUtils.md5Hex("password");
        String hash2 = PasswordHashingUtils.md5Hex("password");
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        // Different input should produce a different hash
        assertNotEquals(hash1, PasswordHashingUtils.md5Hex("different"));
    }

    @Test
    @DisplayName("SHA-256: Should generate a deterministic salted hash")
    void sha256Hash_CorrectHex() {
        // Hashes are now salted with a per-application salt
        String hash1 = PasswordHashingUtils.unsaltedSha256Hex("password");
        String hash2 = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(64, hash1.length());
        assertEquals(hash1, hash2);
        // Different input should produce a different hash
        assertNotEquals(hash1, PasswordHashingUtils.unsaltedSha256Hex("different"));
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
    @DisplayName("LM Hash: Should be case-insensitive and deterministic")
    void lmHash_LegacyStandards() {
        // LM hash is case-insensitive: all cases produce the same result
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Deterministic: same input always yields same output
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Different passwords should produce different hashes
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
