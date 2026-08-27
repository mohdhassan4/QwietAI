package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and validate correctly")
    void md4Hash_SaltedAndValidates() {
        String salted = PasswordHashingUtils.md4Hex("password123");
        // Salted format: saltHex:hashHex
        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidHash(
                        "password123", salted, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.isValidHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and validate correctly")
    void md5Hash_SaltedAndValidates() {
        String salted = PasswordHashingUtils.md5Hex("password");
        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidHash(
                        "password", salted, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.isValidHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and validate correctly")
    void sha256Hash_SaltedAndValidates() {
        String salted = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidHash(
                        "password", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.isValidHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("getHashAsHex with explicit salt: deterministic for same salt")
    void getHashAsHex_ExplicitSalt_Deterministic() {
        byte[] salt = "testsalt".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String hash1 =
                PasswordHashingUtils.getHashAsHex(
                        "password", PasswordHashingUtils.HashAlgorithm.SHA256, salt);
        String hash2 =
                PasswordHashingUtils.getHashAsHex(
                        "password", PasswordHashingUtils.HashAlgorithm.SHA256, salt);
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // Not a real secret — test fixture value
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Not a real secret — test fixture value
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
        // Not a real secret — LM hash outputs are test fixture values (one-way, non-reversible)
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Deterministic: same input always yields same output
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));
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
