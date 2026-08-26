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
        // Salted hash format: "saltHex:hashHex"
        assertTrue(saltedHash.contains(":"), "Hash should contain salt separator");
        // Verification should succeed with correct password
        assertTrue(PasswordHashingUtils.verifyMd4Hex(password, saltedHash));
        // Verification should fail with wrong password
        assertFalse(PasswordHashingUtils.verifyMd4Hex("wrongpassword", saltedHash));
        // Two hashes of same password should differ (different random salts)
        String anotherHash = PasswordHashingUtils.md4Hex(password);
        assertNotEquals(saltedHash, anotherHash);
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.md5Hex(password);
        // Salted hash format: "saltHex:hashHex"
        assertTrue(saltedHash.contains(":"), "Hash should contain salt separator");
        // Verification should succeed with correct password
        assertTrue(PasswordHashingUtils.verifyMd5Hex(password, saltedHash));
        // Verification should fail with wrong password
        assertFalse(PasswordHashingUtils.verifyMd5Hex("wrongpassword", saltedHash));
        // Two hashes of same password should differ (different random salts)
        String anotherHash = PasswordHashingUtils.md5Hex(password);
        assertNotEquals(saltedHash, anotherHash);
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String password = "password";
        String saltedHash = PasswordHashingUtils.unsaltedSha256Hex(password);
        // Salted hash format: "saltHex:hashHex"
        assertTrue(saltedHash.contains(":"), "Hash should contain salt separator");
        // Verification should succeed with correct password
        assertTrue(PasswordHashingUtils.verifySha256Hex(password, saltedHash));
        // Verification should fail with wrong password
        assertFalse(PasswordHashingUtils.verifySha256Hex("wrongpassword", saltedHash));
        // Two hashes of same password should differ (different random salts)
        String anotherHash = PasswordHashingUtils.unsaltedSha256Hex(password);
        assertNotEquals(saltedHash, anotherHash);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // Non-production: test fixture (not a real secret)
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // Non-production: test fixture (not a real secret)
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
    void lmHash_LegacyStandards() {
        // LM Hash converts to uppercase before hashing, so all cases produce the same result
        // Non-production demo fixture: deterministic hash output of well-known test input (not a real secret)
        String hash = PasswordHashingUtils.lmHash("password");

        assertNotNull(hash);
        assertFalse(hash.isEmpty());
        // Case-insensitivity: all variants of "password" produce the same hash
        assertEquals(hash, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash, PasswordHashingUtils.lmHash("pAsSwOrD"));
        // Determinism: same input always produces same output
        assertEquals(hash, PasswordHashingUtils.lmHash("password"));
        // Different input produces different hash
        assertNotEquals(hash, PasswordHashingUtils.lmHash("different"));
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
