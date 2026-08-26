package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String salted = PasswordHashingUtils.md4Hex("password123");
        // Salted format is saltHex:hashHex
        assertTrue(salted.contains(":"));
        assertTrue(PasswordHashingUtils.verifyHash(
                "password123", salted, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(PasswordHashingUtils.verifyHash(
                "wrongpassword", salted, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of the same input should differ due to random salt")
    void md4Hash_UniquePerCall() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String salted = PasswordHashingUtils.md5Hex("password");
        assertTrue(salted.contains(":"));
        assertTrue(PasswordHashingUtils.verifyHash(
                "password", salted, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(PasswordHashingUtils.verifyHash(
                "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String salted = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(salted.contains(":"));
        assertTrue(PasswordHashingUtils.verifyHash(
                "password", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(PasswordHashingUtils.verifyHash(
                "wrong", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // test fixture value, not a real credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // test fixture value, not a real credential
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
        // Known LM hash for "password" (which it converts to "PASSWORD")
        String expected = "e52cac67419a9a224a3b108f3fa6cb6d";

        assertEquals(expected, PasswordHashingUtils.lmHash("password"));
        assertEquals(expected, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(expected, PasswordHashingUtils.lmHash("pAsSwOrD"));
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
