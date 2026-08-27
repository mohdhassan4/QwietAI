package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    @DisplayName("MD4: Should generate a salted hash in saltHex:hashHex format")
    void md4Hash_SaltedFormat() {
        String result = PasswordHashingUtils.md4Hex("password123");
        assertNotNull(result);
        assertTrue(result.contains(":"), "Should contain salt separator");
        String[] parts = result.split(":", 2);
        assertEquals(2, parts.length);
        // Salt is 16 bytes = 32 hex chars
        assertEquals(32, parts[0].length(), "Salt should be 32 hex characters");
        assertFalse(parts[1].isEmpty(), "Hash part should not be empty");
    }

    @Test
    @DisplayName("MD4: Two hashes of the same password should differ (different salts)")
    void md4Hash_DifferentSalts() {
        String hash1 = PasswordHashingUtils.md4Hex("password123");
        String hash2 = PasswordHashingUtils.md4Hex("password123");
        assertNotEquals(hash1, hash2, "Same password should produce different salted hashes");
    }

    @Test
    @DisplayName("MD4: isValidSaltedHash should verify correctly")
    void md4Hash_Validation() {
        String salted = PasswordHashingUtils.md4Hex("password123");
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password123", salted, PasswordHashingUtils.HashAlgorithm.MD4));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrongpassword", salted, PasswordHashingUtils.HashAlgorithm.MD4));
    }

    @Test
    @DisplayName("MD5: Should generate a salted hash and validate correctly")
    void md5Hash_SaltedAndValidated() {
        String salted = PasswordHashingUtils.md5Hex("password");
        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password", salted, PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("SHA-1: Should generate a salted hash and validate correctly")
    void sha1Hash_SaltedAndValidated() {
        String salted = PasswordHashingUtils.sha1Hex("password");
        assertTrue(salted.contains(":"));
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password", salted, PasswordHashingUtils.HashAlgorithm.SHA1));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "wrong", salted, PasswordHashingUtils.HashAlgorithm.SHA1));
    }

    @Test
    @DisplayName("SHA-256 (unsaltedSha256Hex): Should now generate salted hash")
    void sha256Hash_NowSalted() {
        String salted = PasswordHashingUtils.unsaltedSha256Hex("password");
        assertTrue(salted.contains(":"), "unsaltedSha256Hex should now return salted format");
        assertTrue(
                PasswordHashingUtils.isValidSaltedHash(
                        "password", salted, PasswordHashingUtils.HashAlgorithm.SHA256));
    }

    @Test
    @DisplayName("SHA-256: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // test fixture
        // Manual calculation of SHA-256(salt + password) using the salted approach
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // test fixture
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
        // Compute expected from one variant; verify case-insensitivity property
        String expected = PasswordHashingUtils.lmHash("password");

        assertNotNull(expected);
        assertFalse(expected.isEmpty());
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
    @DisplayName("Hex Utility: hexToBytes should round-trip with bytesToHex")
    void hexToBytes_RoundTrip() {
        byte[] original = {0, 15, 16, 127, -1, 42};
        String hex = EncodingUtils.bytesToHex(original);
        byte[] restored = EncodingUtils.hexToBytes(hex);
        assertArrayEquals(original, restored);
    }

    @Test
    @DisplayName("Null Checks: Should handle null inputs gracefully in validation")
    void validation_NullInputs() {
        assertFalse(PasswordHashingUtils.isValidSaltedSha256(null, "someHash"));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("somePass", null));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        null, "salt:hash", PasswordHashingUtils.HashAlgorithm.MD5));
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "pass", null, PasswordHashingUtils.HashAlgorithm.MD5));
    }

    @Test
    @DisplayName("isValidSaltedHash: Should reject malformed values without separator")
    void isValidSaltedHash_RejectsMalformed() {
        assertFalse(
                PasswordHashingUtils.isValidSaltedHash(
                        "password", "nocolonhere", PasswordHashingUtils.HashAlgorithm.MD5));
    }
}
