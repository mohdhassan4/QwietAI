package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md4Hex("password123");
        // Salted hash format: "saltHex:digestHex"
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        // Verify the hash
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrongpassword", hash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of the same input should differ due to random salt")
    void md4Hash_UniqueSalts() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2, "Different salts should produce different outputs");
        // But both should verify
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash1, PasswordHashingUtils.HashAlgorithm.MD4));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password123", hash2, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.md5Hex("password");
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256 (salted): Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String hash = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(hash.contains(":"), "Salted hash should contain separator");
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "password", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
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
    @DisplayName("PBKDF2: Should produce salted hashes and verify correctly")
    void pbkdf2Hash_SaltedAndVerifiable() {
        String hash1 = PasswordHashingUtils.pbkdf2Hash("password");
        String hash2 = PasswordHashingUtils.pbkdf2Hash("password");

        // Different random salts produce different outputs
        assertNotEquals(hash1, hash2);

        // Salted hash format: "saltHex:hashHex"
        assertTrue(hash1.contains(":"), "PBKDF2 hash should contain separator");
        assertTrue(hash2.contains(":"), "PBKDF2 hash should contain separator");

        // Both should verify against the correct password
        assertTrue(PasswordHashingUtils.verifyPbkdf2("password", hash1));
        assertTrue(PasswordHashingUtils.verifyPbkdf2("password", hash2));

        // Wrong password should not verify
        assertFalse(PasswordHashingUtils.verifyPbkdf2("wrong", hash1));

        // PBKDF2 is case-sensitive (unlike legacy LM hash)
        assertFalse(PasswordHashingUtils.verifyPbkdf2("PASSWORD", hash1));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Hex Utility: hexToBytes should round-trip with bytesToHex")
    void hexToBytes_RoundTrip() {
        byte[] input = {0, 15, 16, 127, -1};
        String hex = EncodingUtils.bytesToHex(input);
        byte[] output = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(input, output);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        null, "salt:hash", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "pass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }
}
