package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String rawPassword = "password123"; // test fixture (not a real secret)
        String salted = PasswordHashingUtils.md4Hex(rawPassword);

        // Format should be saltHex:digestHex
        assertTrue(salted.contains(":"), "Salted hash must contain separator");
        String[] parts = salted.split(":", 2);
        assertEquals(32, parts[0].length(), "Salt should be 16 bytes (32 hex chars)");

        // Two calls produce different salts
        String salted2 = PasswordHashingUtils.md4Hex(rawPassword);
        assertNotEquals(salted, salted2);

        // Verification succeeds for correct password
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        rawPassword, salted, PasswordHashingUtils.HashAlgorithm.MD4));
        // Verification fails for wrong password
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String rawPassword = "password"; // test fixture (not a real secret)
        String salted = PasswordHashingUtils.md5Hex(rawPassword);

        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        rawPassword, salted, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String rawPassword = "password"; // test fixture (not a real secret)
        String salted = PasswordHashingUtils.saltedSha256Hex(rawPassword);

        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.verifySaltedHash(
                        rawPassword, salted, PasswordHashingUtils.HashAlgorithm.SHA256));
        assertFalse(
                PasswordHashingUtils.verifySaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // test fixture credential (not a real secret)
        // sha256Hex with string salt returns only the digest hex
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // test fixture credential (not a real secret)
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and produce consistent AES-based hash")
    void lmHash_LegacyStandards() {
        // Expected AES/CBC/PKCS5Padding-based hash digest for "password" (not a secret - deterministic hash output)
        String expected = "f848811aca4ec96b94f82d053cb94d4445f774f9da811f564e48042ad33007b5";

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
}
