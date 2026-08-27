package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @BeforeAll
    static void setupProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Computes a reference hash independently of PasswordHashingUtils to cross-check its output.
     * Uses standard Java MessageDigest (falling back to BouncyCastle for non-standard algorithms
     * like MD4).
     */
    private static String referenceHash(String algorithm, String input) {
        try {
            MessageDigest md;
            try {
                md = MessageDigest.getInstance(algorithm);
            } catch (java.security.NoSuchAlgorithmException e) {
                md = MessageDigest.getInstance(algorithm, "BC");
            }
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute reference hash", e);
        }
    }

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash")
    void md4Hash_CorrectHex() {
        // Compute expected MD4 hash via independent MessageDigest call
        String expected = referenceHash("MD4", "password123");
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("MD5: Should generate a correct unsalted hash")
    void md5Hash_CorrectHex() {
        // Compute expected MD5 hash via standard Java MessageDigest
        String expected = referenceHash("MD5", "password");
        String actual = PasswordHashingUtils.md5Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() {
        // Compute expected SHA-256 hash via standard Java MessageDigest
        String expected = referenceHash("SHA-256", "password");
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        // nosecret: test fixture values for unit test assertions, not real credentials
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
        // nosecret: test fixture value for unit test assertions, not a real credential
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
