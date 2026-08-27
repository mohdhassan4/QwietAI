package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify it")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123";
        String saltedHash = PasswordHashingUtils.md4Hex(password);

        // Salted hash should be in salt:hash format
        assertTrue(saltedHash.contains(":"), "Hash should be in salt:hash format");
        String[] parts = saltedHash.split(":", 2);
        assertEquals(2, parts.length);
        // Salt should be 32 hex chars (16 bytes)
        assertEquals(32, parts[0].length());

        // Verification should succeed
        assertTrue(PasswordHashingUtils.verifyHash(password, saltedHash,
                PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(PasswordHashingUtils.verifyHash("wrong", saltedHash,
                PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify it")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.md5Hex(password);

        assertTrue(saltedHash.contains(":"), "Hash should be in salt:hash format");
        assertTrue(PasswordHashingUtils.verifyHash(password, saltedHash,
                PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(PasswordHashingUtils.verifyHash("wrong", saltedHash,
                PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("MD5: Two hashes for the same password should differ (unique salts)")
    void md5Hash_UniqueSalts() {
        String hash1 = PasswordHashingUtils.md5Hex("password");
        String hash2 = PasswordHashingUtils.md5Hex("password");
        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("SHA-256: Should generate salted hash via unsaltedSha256Hex (now salted)")
    void sha256Hash_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.unsaltedSha256Hex(password);

        assertTrue(saltedHash.contains(":"), "Hash should be in salt:hash format");
        assertTrue(PasswordHashingUtils.verifyHash(password, saltedHash,
                PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(PasswordHashingUtils.verifyHash("wrong", saltedHash,
                PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = PasswordHashingUtils.generateSalt();
        String rawPassword = "test-only-not-real";
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("test-wrong-input", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "test-only-bcrypt-input";
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

    @Test
    @DisplayName("verifyHash: Should return false for null and malformed inputs")
    void verifyHash_NullAndMalformed() {
        assertFalse(PasswordHashingUtils.verifyHash(null, "salt:hash",
                PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(PasswordHashingUtils.verifyHash("password", null,
                PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(PasswordHashingUtils.verifyHash("password", "nocolon",
                PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("generateSalt: Should produce 32-character hex strings")
    void generateSalt_Length() {
        String salt = PasswordHashingUtils.generateSalt();
        assertEquals(32, salt.length());
        assertTrue(salt.matches("[0-9a-f]+"));
    }
}
