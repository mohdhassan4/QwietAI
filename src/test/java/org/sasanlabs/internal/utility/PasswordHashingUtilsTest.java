package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and validate correctly")
    void md4Hash_SaltedAndValidatable() {
        String password = "password123";
        String salted1 = PasswordHashingUtils.md4Hex(password);
        String salted2 = PasswordHashingUtils.md4Hex(password);

        // Salted hashes should differ due to random salt
        assertNotEquals(salted1, salted2);

        // Both should validate against the original password
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        password, salted1, PasswordHashingUtils.HashAlgorithm.MD4));
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        password, salted2, PasswordHashingUtils.HashAlgorithm.MD4));

        // Wrong password should fail
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrong", salted1, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and validate correctly")
    void md5Hash_SaltedAndValidatable() {
        String password = "password";
        String salted = PasswordHashingUtils.md5Hex(password);

        // Should contain salt separator
        assertTrue(salted.contains(":"));

        // Should validate against the original password
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        password, salted, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-1: Should generate a salted hash and validate correctly")
    void sha1Hash_SaltedAndValidatable() {
        String password = "testPassword";
        String salted = PasswordHashingUtils.sha1Hex(password);

        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        password, salted, PasswordHashingUtils.HashAlgorithm.SHA1));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.SHA1));
    }

    @Test
    @DisplayName("SHA-256: Salted hash should validate correctly")
    void sha256Hash_SaltedAndValidatable() {
        String password = "password";
        String salted = PasswordHashingUtils.saltedSha256Hex(password);

        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        password, salted, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("getHashAsHex with explicit salt produces deterministic output")
    void getHashAsHex_WithSalt_Deterministic() {
        byte[] salt = "fixedsalt1234567".getBytes();
        String hash1 =
                PasswordHashingUtils.getHashAsHex(
                        "password", PasswordHashingUtils.HashAlgorithm.SHA256, salt);
        String hash2 =
                PasswordHashingUtils.getHashAsHex(
                        "password", PasswordHashingUtils.HashAlgorithm.SHA256, salt);
        assertEquals(hash1, hash2);

        // Different salt produces different hash
        byte[] salt2 = "othersalt1234567".getBytes();
        String hash3 =
                PasswordHashingUtils.getHashAsHex(
                        "password", PasswordHashingUtils.HashAlgorithm.SHA256, salt2);
        assertNotEquals(hash1, hash3);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123";
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
    @DisplayName("LM Hash: Should be case-insensitive and match legacy standards")
    void lmHash_LegacyStandards() {
        // Known LM hash for "password" (converts to "PASSWORD") — deterministic test vector
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
    @DisplayName("Hex Utility: hexToBytes should roundtrip with bytesToHex")
    void hexToBytes_Roundtrip() {
        byte[] original = {0, 15, 16, 127, -1};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] recovered = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, recovered);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        null, "someHash", PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "somePass", null, PasswordHashingUtils.HashAlgorithm.SHA256));
    }
}
