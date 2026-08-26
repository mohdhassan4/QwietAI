package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a salted hash that differs from the raw unsalted digest")
    void md4Hash_SaltedAndDeterministic() {
        // With the application-level pepper, the result should be deterministic but different
        // from the well-known unsalted MD4 of "password123"
        String unsaltedKnown = "fc7b71b67e964466cec486ab12f4b558";
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertNotNull(actual);
        assertNotEquals(unsaltedKnown, actual, "Hash must include salt/pepper and differ from unsalted value");
        // Deterministic: same input yields same output
        assertEquals(actual, PasswordHashingUtils.md4Hex("password123"));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash that differs from the raw unsalted digest")
    void md5Hash_SaltedAndDeterministic() {
        // With the application-level pepper, the result should be deterministic but different
        // from the well-known unsalted MD5 of "password"
        String unsaltedKnown = "5f4dcc3b5aa765d61d8327deb882cf99";
        String actual = PasswordHashingUtils.md5Hex("password");
        assertNotNull(actual);
        assertNotEquals(unsaltedKnown, actual, "Hash must include salt/pepper and differ from unsalted value");
        // Deterministic: same input yields same output
        assertEquals(actual, PasswordHashingUtils.md5Hex("password"));
    }

    @Test
    @DisplayName("SHA-256: Should generate a salted hash that differs from the raw unsalted digest")
    void sha256Hash_SaltedAndDeterministic() {
        // With the application-level pepper, the result should be deterministic but different
        // from the well-known unsalted SHA-256 of "password"
        String unsaltedKnown = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertNotNull(actual);
        assertNotEquals(unsaltedKnown, actual, "Hash must include salt/pepper and differ from unsalted value");
        // Deterministic: same input yields same output
        assertEquals(actual, PasswordHashingUtils.unsaltedSha256Hex("password"));
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
}
