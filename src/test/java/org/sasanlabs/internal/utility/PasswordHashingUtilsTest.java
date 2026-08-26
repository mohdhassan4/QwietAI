package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String saltedHash = PasswordHashingUtils.md4Hex("password123");
        // Salted hashes contain separator
        assertTrue(saltedHash.contains(":"));
        // Two hashes for the same input differ (random salt)
        String saltedHash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(saltedHash, saltedHash2);
        // Verification succeeds with correct password
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));
        // Verification fails with wrong password
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String saltedHash = PasswordHashingUtils.md5Hex("password");
        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Salted hash should verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String saltedHash = PasswordHashingUtils.saltedSha256Hex("password");
        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // nosecret: test fixture value
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // nosecret: test fixture value
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
        // LM hash must be deterministic: same input always produces same output
        // non-secret: computed hash output used as test fixture (not a credential)
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertEquals(hash1, hash2);

        // LM hash is case-insensitive: all case variations produce the same hash
        assertEquals(hash1, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash1, PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Output should be a hex string (only hex characters)
        assertTrue(hash1.matches("[0-9a-f]+"));

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
