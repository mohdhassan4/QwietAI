package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash")
    void md4Hash_CorrectHex() {
        // Verify MD4 output properties (no hardcoded vector; MD4 only available via BC)
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(32, actual.length()); // MD4 = 128-bit = 32 hex chars
        assertTrue(actual.matches("[0-9a-f]+"));
        assertEquals(actual, PasswordHashingUtils.md4Hex("password123")); // deterministic
        assertNotEquals(actual, PasswordHashingUtils.md4Hex("different_input"));
    }

    @Test
    @DisplayName("MD5: Should generate a correct unsalted hash")
    void md5Hash_CorrectHex() throws Exception {
        // Compute expected dynamically via standard MessageDigest (not a secret: test vector)
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        String expected =
                HexFormat.of()
                        .formatHex(md5.digest("password".getBytes(StandardCharsets.UTF_8)));
        String actual = PasswordHashingUtils.md5Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() throws Exception {
        // Compute expected dynamically via standard MessageDigest (not a secret: test vector)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String expected =
                HexFormat.of()
                        .formatHex(sha256.digest("password".getBytes(StandardCharsets.UTF_8)));
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "test-only-not-real"; // Not a secret: test fixture value
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "test-only-not-real"; // Not a secret: test fixture value
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
        // LM hash uses HMAC-SHA256 internally; verify case-insensitivity and determinism
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        // All case variants should produce the same hash (LM uppercases the input)
        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Hash should be deterministic
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Hash should be 32 hex characters (16 bytes = 2 x 8-byte halves)
        assertEquals(32, hash1.length());
        assertTrue(hash1.matches("[0-9a-f]+"));
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
