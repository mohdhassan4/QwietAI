package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate unique salted hashes and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123";
        String hash1 = PasswordHashingUtils.md4Hex(password);
        String hash2 = PasswordHashingUtils.md4Hex(password);

        // Each call produces a unique salt, so outputs differ
        assertNotEquals(hash1, hash2);

        // Format is saltHex:hashHex
        assertTrue(hash1.contains(":"));

        // Verification succeeds
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        password, hash1, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", hash1, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate unique salted hashes and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password";
        String hash1 = PasswordHashingUtils.md5Hex(password);
        String hash2 = PasswordHashingUtils.md5Hex(password);

        // Each call produces a unique salt, so outputs differ
        assertNotEquals(hash1, hash2);

        // Format is saltHex:hashHex
        assertTrue(hash1.contains(":"));

        // Verification succeeds
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        password, hash1, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", hash1, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate unique salted hashes and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String password = "password";
        String hash1 = PasswordHashingUtils.unsaltedSha256Hex(password);
        String hash2 = PasswordHashingUtils.unsaltedSha256Hex(password);

        // Each call produces a unique salt, so outputs differ
        assertNotEquals(hash1, hash2);

        // Format is saltHex:hashHex
        assertTrue(hash1.contains(":"));

        // Verification succeeds
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        password, hash1, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", hash1, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // Test fixture credential — not a production secret
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Test fixture credential — not a production secret
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should produce unique salted hashes and validate correctly")
    void lmHash_UniqueSaltAndValidation() {
        String password = "password";
        String hash1 = PasswordHashingUtils.lmHash(password);
        String hash2 = PasswordHashingUtils.lmHash(password);

        // Each call uses a unique salt, so hashes differ
        assertNotEquals(hash1, hash2);

        // Both should validate correctly
        assertTrue(PasswordHashingUtils.isValidLmHash(password, hash1));
        assertTrue(PasswordHashingUtils.isValidLmHash(password, hash2));

        // Wrong password should not validate
        assertFalse(PasswordHashingUtils.isValidLmHash("wrong", hash1));

        // Null inputs should be handled gracefully
        assertFalse(PasswordHashingUtils.isValidLmHash(null, hash1));
        assertFalse(PasswordHashingUtils.isValidLmHash(password, null));
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
