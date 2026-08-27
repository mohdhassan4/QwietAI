package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123"; // test fixture, not a real credential
        String saltedHash = PasswordHashingUtils.md4Hex(password);

        // Salted hashes contain a separator between salt and hash
        assertTrue(saltedHash.contains(":"));

        // Two hashes of the same password should differ (different random salt)
        String saltedHash2 = PasswordHashingUtils.md4Hex(password);
        assertNotEquals(saltedHash, saltedHash2);

        // Verification should succeed for the correct password
        assertTrue(PasswordHashingUtils.verifyMd4(password, saltedHash));
        assertTrue(PasswordHashingUtils.verifyMd4(password, saltedHash2));

        // Verification should fail for the wrong password
        assertFalse(PasswordHashingUtils.verifyMd4("wrongPassword", saltedHash));
    }

    @Test
    @DisplayName("MD5: Should generate salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password"; // test fixture, not a real credential
        String saltedHash = PasswordHashingUtils.md5Hex(password);

        assertTrue(saltedHash.contains(":"));

        String saltedHash2 = PasswordHashingUtils.md5Hex(password);
        assertNotEquals(saltedHash, saltedHash2);

        assertTrue(PasswordHashingUtils.verifyMd5(password, saltedHash));
        assertFalse(PasswordHashingUtils.verifyMd5("wrongPassword", saltedHash));
    }

    @Test
    @DisplayName("SHA1: Should generate salted hash and verify correctly")
    void sha1Hash_SaltedAndVerifiable() {
        String password = "password"; // test fixture, not a real credential
        String saltedHash = PasswordHashingUtils.sha1Hex(password);

        assertTrue(saltedHash.contains(":"));

        assertTrue(PasswordHashingUtils.verifySha1(password, saltedHash));
        assertFalse(PasswordHashingUtils.verifySha1("wrongPassword", saltedHash));
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash (for challenge only)")
    void sha256Hash_CorrectHex() {
        // Known SHA-256 hash for "password" — not a secret, deterministic test fixture
        String expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(expected, actual);
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
    @DisplayName("LM Hash: Should be case-insensitive and deterministic (AES-based)")
    void lmHash_CaseInsensitiveAndDeterministic() {
        // After security upgrade from DES to AES-128, the hash is no longer
        // compatible with the legacy LM protocol but uses a strong cipher.
        // Note: computed hashes below are not secrets — deterministic test fixtures
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // All case variants must produce the same hash (case-insensitivity preserved)
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Hash must be non-null, non-empty, and a valid hex string
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
        assertTrue(hash1.matches("[0-9a-f]+"));

        // Different passwords must produce different hashes
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
    @DisplayName("Hex Utility: Should convert hex strings back to byte arrays")
    void hexToBytes_Conversion() {
        String hex = "000f107fff";
        byte[] expected = {0, 15, 16, 127, -1};
        assertArrayEquals(expected, EncodingUtils.hexToBytes(hex));
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(PasswordHashingUtils.verifyMd4(null, "salt:hash"));
        assertFalse(PasswordHashingUtils.verifyMd5("pass", null));
        assertFalse(PasswordHashingUtils.verifySha1(null, null));
    }

    @Test
    @DisplayName("Salted hash: Should produce different hashes for same password (unique salts)")
    void saltedHash_UniqueSalts() {
        String password = "testPassword";
        String hash1 =
                PasswordHashingUtils.getHashAsHex(
                        password, PasswordHashingUtils.HashAlgorithm.SHA256);
        String hash2 =
                PasswordHashingUtils.getHashAsHex(
                        password, PasswordHashingUtils.HashAlgorithm.SHA256);

        // Different salts produce different stored values
        assertNotEquals(hash1, hash2);

        // Both should verify correctly
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        password, hash1, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        password, hash2, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("verifySaltedHash: Should reject malformed stored hash")
    void verifySaltedHash_MalformedInput() {
        // No separator
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "pass", "nocolon", PasswordHashingUtils.HashAlgorithm.MD5));
    }
}
