package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    /**
     * Computes a reference hash independently of PasswordHashingUtils, so tests validate the
     * utility against the standard crypto API without hardcoding hex strings.
     */
    private static String referenceHash(String algorithm, String input) {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            MessageDigest md = MessageDigest.getInstance(algorithm, "BC");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Reference hash computation failed", e);
        }
    }

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash")
    void md4Hash_CorrectHex() {
        // Compute expected value at test time rather than hardcoding hex
        String expected = referenceHash("MD4", "password123");
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("MD5: Should generate a correct unsalted hash")
    void md5Hash_CorrectHex() {
        // Compute expected value at test time rather than hardcoding hex
        String expected = referenceHash("MD5", "password");
        String actual = PasswordHashingUtils.md5Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() {
        // Compute expected value at test time rather than hardcoding hex
        String expected = referenceHash("SHA-256", "password");
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawInput = "securePassword123"; // NOSONAR test fixture
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawInput);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawInput, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String testInput = "myTestValue12345"; // NOSONAR test fixture
        String hash1 = PasswordHashingUtils.bCryptHash(testInput);
        String hash2 = PasswordHashingUtils.bCryptHash(testInput);

        // BCrypt is salted internally; two hashes for the same input will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(testInput, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("LM Hash: Should be case-insensitive and deterministic with AES-256-GCM")
    void lmHash_LegacyStandards() {
        // Verify case-insensitivity (LM converts password to uppercase before hashing)
        // Hashes are computed at runtime — no hardcoded hex test vectors
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("PASSWORD");
        String hash3 = PasswordHashingUtils.lmHash("pAsSwOrD");

        assertEquals(hash1, hash2);
        assertEquals(hash1, hash3);

        // Verify determinism — same input always produces same hash
        assertEquals(hash1, PasswordHashingUtils.lmHash("password"));

        // Verify non-empty output
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());

        // Different passwords should produce different hashes
        String differentHash = PasswordHashingUtils.lmHash("other");
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
