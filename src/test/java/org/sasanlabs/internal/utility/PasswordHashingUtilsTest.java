package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should produce consistent hashes for the same input")
    void md4Hash_Consistent() {
        String first = PasswordHashingUtils.md4Hex("password123");
        String second = PasswordHashingUtils.md4Hex("password123");
        assertEquals(first, second);
        assertNotNull(first);
        assertEquals(32, first.length());
    }

    @Test
    @DisplayName("MD5: Should produce consistent hashes for the same input")
    void md5Hash_Consistent() {
        String first = PasswordHashingUtils.md5Hex("password");
        String second = PasswordHashingUtils.md5Hex("password");
        assertEquals(first, second);
        assertNotNull(first);
        assertEquals(32, first.length());
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should produce consistent hashes for the same input")
    void sha256Hash_Consistent() {
        String first = PasswordHashingUtils.unsaltedSha256Hex("password");
        String second = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(first, second);
        assertNotNull(first);
        assertEquals(64, first.length());
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword =
                System.getenv().getOrDefault("TEST_PASSWORD", "securePassword123");
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password =
                System.getenv().getOrDefault("TEST_BCRYPT_PASSWORD", "mySecretPassword");
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and match legacy standards")
    void lmHash_LegacyStandards() {
        String lower = PasswordHashingUtils.lmHash("password");
        String upper = PasswordHashingUtils.lmHash("PASSWORD");
        String mixed = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertEquals(lower, upper);
        assertEquals(lower, mixed);
        assertNotNull(lower);
        assertEquals(32, lower.length());
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
