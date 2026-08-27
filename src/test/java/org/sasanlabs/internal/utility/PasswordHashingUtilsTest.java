package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PasswordHashingUtilsTest {

    @Test
    @DisplayName("MD4: Should generate salted hash and verify correctly")
    void md4Hash_SaltedAndVerifiable() {
        String password = "password123"; // nosecret: test fixture
        String hash1 = PasswordHashingUtils.md4Hex(password);
        String hash2 = PasswordHashingUtils.md4Hex(password);

        // Salted: two hashes of the same password differ (different random salt)
        assertNotEquals(hash1, hash2);

        // Format is hexSalt:hexHash
        assertTrue(hash1.contains(":"));
        String[] parts = hash1.split(":", 2);
        assertEquals(32, parts[0].length()); // 16 bytes = 32 hex chars
        assertTrue(parts[0].matches("[0-9a-f]+"));
        assertTrue(parts[1].matches("[0-9a-f]+"));

        // Verify works
        assertTrue(PasswordHashingUtils.verifyMd4Hex(password, hash1));
        assertTrue(PasswordHashingUtils.verifyMd4Hex(password, hash2));
        assertFalse(PasswordHashingUtils.verifyMd4Hex("wrongPass", hash1));
    }

    @Test
    @DisplayName("MD5: Should generate salted hash and verify correctly")
    void md5Hash_SaltedAndVerifiable() {
        String password = "password"; // nosecret: test fixture
        String hash1 = PasswordHashingUtils.md5Hex(password);
        String hash2 = PasswordHashingUtils.md5Hex(password);

        // Salted: different each time
        assertNotEquals(hash1, hash2);

        // Verify works
        assertTrue(PasswordHashingUtils.verifyMd5Hex(password, hash1));
        assertTrue(PasswordHashingUtils.verifyMd5Hex(password, hash2));
        assertFalse(PasswordHashingUtils.verifyMd5Hex("wrongPass", hash1));
    }

    @Test
    @DisplayName("SHA-256 (salted): Should generate salted hash and verify correctly")
    void sha256Hash_SaltedAndVerifiable() {
        String password = "password"; // nosecret: test fixture
        String hash1 = PasswordHashingUtils.unsaltedSha256Hex(password);
        String hash2 = PasswordHashingUtils.unsaltedSha256Hex(password);

        // Salted: different each time
        assertNotEquals(hash1, hash2);

        // Verify works
        assertTrue(PasswordHashingUtils.verifySha256Hex(password, hash1));
        assertTrue(PasswordHashingUtils.verifySha256Hex(password, hash2));
        assertFalse(PasswordHashingUtils.verifySha256Hex("wrongPass", hash1));
    }

    @Test
    @DisplayName("SHA-256 with string salt: Should correctly validate salted hashes with separator")
    void isValidSaltedSha256_CorrectValidation() {
        String salt = "random_salt";
        String rawPassword = "securePassword123"; // nosecret: test fixture credential
        // Manual calculation of SHA-256(salt + password)
        String hash = PasswordHashingUtils.sha256Hex(salt, rawPassword);
        String storedValue = salt + ":" + hash;

        assertTrue(PasswordHashingUtils.isValidSaltedSha256(rawPassword, storedValue));
        assertFalse(PasswordHashingUtils.isValidSaltedSha256("wrongPass", storedValue));
    }

    @Test
    @DisplayName("BCrypt: Should validate successfully even though hashes are unique each time")
    void bcrypt_UniqueGenerationAndValidation() {
        String password = "mySecretPassword"; // nosecret: test fixture credential
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
        // The hash must be deterministic: same input always produces the same output
        String hash1 = PasswordHashingUtils.lmHash("password");
        String hash2 = PasswordHashingUtils.lmHash("password");
        assertEquals(hash1, hash2);

        // Case-insensitive: different capitalizations produce the same hash
        assertEquals(hash1, PasswordHashingUtils.lmHash("PASSWORD"));
        assertEquals(hash1, PasswordHashingUtils.lmHash("pAsSwOrD"));

        // Different passwords produce different hashes
        assertNotEquals(hash1, PasswordHashingUtils.lmHash("different"));

        // Hash is a non-empty hex string
        assertNotNull(hash1);
        assertFalse(hash1.isEmpty());
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
        assertFalse(PasswordHashingUtils.verifyMd4Hex(null, "someSaltedHash"));
        assertFalse(PasswordHashingUtils.verifyMd5Hex("somePass", null));
    }

    @Test
    @DisplayName("SHA1: Should generate salted hash and verify correctly")
    void sha1Hash_SaltedAndVerifiable() {
        String password = "testPassword"; // nosecret: test fixture
        String hash1 = PasswordHashingUtils.sha1Hex(password);
        String hash2 = PasswordHashingUtils.sha1Hex(password);

        // Salted: different each time
        assertNotEquals(hash1, hash2);

        // Verify works
        assertTrue(PasswordHashingUtils.verifySha1Hex(password, hash1));
        assertFalse(PasswordHashingUtils.verifySha1Hex("wrongPass", hash1));
    }
}
