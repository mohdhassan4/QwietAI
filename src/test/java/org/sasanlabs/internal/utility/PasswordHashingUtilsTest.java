package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash that verifies correctly")
    void md4Hash_SaltedAndVerifiable() {
        String saltedHash = PasswordHashingUtils.md4Hex("password123");
        // Salted hash format: saltHex:hashHex
        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password123", saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrongPassword", saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of same input should differ due to random salt")
    void md4Hash_NonDeterministic() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash that verifies correctly")
    void md5Hash_SaltedAndVerifiable() {
        String saltedHash = PasswordHashingUtils.md5Hex("password");
        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrongPassword", saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash that verifies correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String saltedHash = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        "password", saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrongPassword", saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // test fixture, not a real credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // test fixture, not a real credential
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
        // LM hash converts input to uppercase, so all case variants must produce the same hash.
        // Values computed at runtime by lmHash — deterministic hash outputs, not secrets.
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Different passwords should produce different hashes
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
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
