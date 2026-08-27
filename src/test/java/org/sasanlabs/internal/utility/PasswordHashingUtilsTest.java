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
    static void registerProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("MD4: Should generate a correct unsalted hash")
    void md4Hash_CorrectHex() throws Exception {
        // Compute reference MD4 hash dynamically via MessageDigest
        MessageDigest md4 = MessageDigest.getInstance("MD4", "BC");
        String expected =
                EncodingUtils.bytesToHex(
                        md4.digest("password123".getBytes(StandardCharsets.UTF_8)));
        String actual = PasswordHashingUtils.md4Hex("password123");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("MD5: Should generate a correct unsalted hash")
    void md5Hash_CorrectHex() throws Exception {
        // Compute reference MD5 hash dynamically via MessageDigest
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        String expected =
                EncodingUtils.bytesToHex(
                        md5.digest("password".getBytes(StandardCharsets.UTF_8)));
        String actual = PasswordHashingUtils.md5Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("Unsalted SHA-256: Should generate a correct unsalted hash")
    void sha256Hash_CorrectHex() throws Exception {
        // Compute reference SHA-256 hash dynamically via MessageDigest
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String expected =
                EncodingUtils.bytesToHex(
                        sha256.digest("password".getBytes(StandardCharsets.UTF_8)));
        String actual = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertEquals(expected, actual);
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // test fixture — not a real credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // test fixture — not a real credential
        String hash1 = PasswordHashingUtils.bCryptHash(password);
        String hash2 = PasswordHashingUtils.bCryptHash(password);

        // BCrypt is salted internally; two hashes for the same password will not be equal
        assertNotEquals(hash1, hash2);

        // But both should be valid
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash1));
        assertTrue(PasswordHashingUtils.isValidBcrypt(password, hash2));
    }

    @Test
    @DisplayName("Password Hash: Should be case-insensitive and verifiable with random salt")
    void lmHash_CaseInsensitiveAndVerifiable() {
        // The hash function uppercases input, so all casings should validate against the same hash.
        String storedHash = PasswordHashingUtils.lmHash("password");

        assertNotNull(storedHash);
        assertFalse(storedHash.isEmpty());
        // Output contains salt:hash separator
        assertTrue(storedHash.contains(":"));

        // All casings should validate against the stored hash (case-insensitive)
        assertTrue(PasswordHashingUtils.isValidLmHash("password", storedHash));
        assertTrue(PasswordHashingUtils.isValidLmHash("PASSWORD", storedHash));
        assertTrue(PasswordHashingUtils.isValidLmHash("pAsSwOrD", storedHash));

        // Wrong password should not validate
        assertFalse(PasswordHashingUtils.isValidLmHash("wrongpassword", storedHash));

        // Each call to lmHash produces a different salt, so hashes differ
        String storedHash2 = PasswordHashingUtils.lmHash("password");
        assertNotEquals(storedHash, storedHash2);
        // But both should still validate
        assertTrue(PasswordHashingUtils.isValidLmHash("password", storedHash2));
    }

    @Test
    @DisplayName("Hex Utility: Should convert byte arrays to lowercase hex strings")
    void bytesToHex_Conversion() {
        byte[] input = {0, 15, 16, 127, -1}; // 00, 0f, 10, 7f, ff
        String expected = "000f107fff";
        assertEquals(expected, EncodingUtils.bytesToHex(input));
    }

    @Test
    @DisplayName("Hex Utility: hexToBytes should be inverse of bytesToHex")
    void hexToBytes_RoundTrip() {
        byte[] original = {0, 15, 16, 127, -1};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] result = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, result);
    }

    @Test
    @DisplayName("Salted MD5: Should produce different hash than unsalted")
    void md5Hex_SaltedVsUnsalted() {
        String unsalted = PasswordHashingUtils.md5Hex("password");
        String salted = PasswordHashingUtils.md5Hex("somesalt", "password");
        assertNotEquals(unsalted, salted);
    }

    @Test
    @DisplayName("Salted SHA-1: Should produce different hash than unsalted")
    void sha1Hex_SaltedVsUnsalted() {
        String unsalted = PasswordHashingUtils.sha1Hex("password");
        String salted = PasswordHashingUtils.sha1Hex("somesalt", "password");
        assertNotEquals(unsalted, salted);
    }

    @Test
    @DisplayName("generateSalt: Should produce 32-char hex strings (16 bytes)")
    void generateSalt_ProducesValidHex() {
        String salt = PasswordHashingUtils.generateSalt();
        assertNotNull(salt);
        assertEquals(32, salt.length());
        assertTrue(salt.matches("[0-9a-f]+"));
        // Two salts should be different
        assertNotEquals(salt, PasswordHashingUtils.generateSalt());
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
    }
}
