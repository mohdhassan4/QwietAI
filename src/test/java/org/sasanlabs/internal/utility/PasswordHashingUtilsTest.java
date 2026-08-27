package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123";
        String saltedHash = PasswordHashingUtils.md4Hex(password);

        // Salted hashes contain a separator between salt and hash
        assertTrue(saltedHash.contains(":"));

        // Verification should succeed with the correct password
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        password, saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));

        // Verification should fail with wrong password
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD4: Two hashes of same password should differ due to random salt")
    void md4Hash_UniquePerCall() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.md5Hex(password);

        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        password, saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("Salted SHA-256: Should generate a salted hash via saltedSha256Hex")
    void saltedSha256Hex_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.saltedSha256Hex(password);

        assertTrue(saltedHash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        password, saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "wrong", saltedHash, PasswordHashingUtils.HashAlgorithm.SHA256));
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
    @DisplayName("LM Hash: Should be deterministic and case-insensitive")
    void lmHash_DeterministicAndCaseInsensitive() {
        // LM hash is case-insensitive: all casings of the same password produce the same hash
        // Non-secret: LM hashes of well-known demo inputs, used only for deterministic test verification
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Deterministic: same input always produces same output
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Different passwords produce different hashes
        assertNotEquals(hash1, PasswordHashingUtils.lmHash("different"));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        // Non-secret: trivial hex encoding of known byte array for test verification
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Hex Utility: hexToBytes should round-trip with bytesToHex")
    void hexToBytes_RoundTrip() {
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
                PasswordHashingUtils.verifyHash(
                        null, "salt:hash", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifyHash(
                        "pass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("getHashAsHex with explicit salt should be verifiable")
    void getHashAsHex_ExplicitSalt() {
        byte[] salt = PasswordHashingUtils.generateSalt();
        String hash = PasswordHashingUtils.getHashAsHex(
                "testInput", PasswordHashingUtils.HashAlgorithm.SHA256, salt);

        assertTrue(hash.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifyHash(
                        "testInput", hash, PasswordHashingUtils.HashAlgorithm.SHA256));
    }
}
