package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and validate correctly")
    void md4Hash_SaltedAndValidatable() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Hash format is "saltHex:hashHex"
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrongPassword", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of the same password should differ (unique salts)")
    void md4Hash_UniqueSalts() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and validate correctly")
    void md5Hash_SaltedAndValidatable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrongPassword", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and validate correctly")
    void sha256Hash_SaltedAndValidatable() {
        String hash = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrongPassword", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
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
        // LM hash should produce the same result regardless of case
        String hashLower = PasswordHashingUtils.lmHash("password");
        String hashUpper = PasswordHashingUtils.lmHash("PASSWORD");
        String hashMixed = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hashLower);
        assertFalse(hashLower.isEmpty());

        // Case insensitive: all variants produce the same hash
        assertEquals(hashLower, hashUpper);
        assertEquals(hashLower, hashMixed);

        // Deterministic: same input always produces the same output
        assertEquals(hashLower, PasswordHashingUtils.lmHash("password"));

        // Different passwords should produce different hashes
        String differentHash = PasswordHashingUtils.lmHash("other");
        assertNotEquals(hashLower, differentHash);
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
