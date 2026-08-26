package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.sasanlabs.internal.utility.exception.EncryptionException;

class EncryptionUtilsTest {

    @Test
    @DisplayName("Caesar Cipher: Should shift characters by 3 and wrap around the alphabet")
    void caesarCipher_CorrectShift() throws EncryptionException {
        // Basic shift
        assertEquals("def", EncryptionUtils.caesarCipher("abc", 3));

        // Wrapping shift (z -> c)
        assertEquals("abc", EncryptionUtils.caesarCipher("xyz", 3));

        // Case preservation
        assertEquals("Abc", EncryptionUtils.caesarCipher("Xyz", 3));

        // Non-alphabetic characters remain unchanged
        assertEquals("123! @#", EncryptionUtils.caesarCipher("123! @#", 3));
    }

    @Test
    @DisplayName(
            "Custom Cipher: Should reverse the string and return a valid Base64 encoded string")
    void customCipher_ReverseAndBase64() throws EncryptionException {
        String input = "password";
        String reversed = "drowssap";
        String expectedBase64 = EncodingUtils.encodeBase64(reversed);

        assertEquals(expectedBase64, EncryptionUtils.customCipher(input));
    }

    @Test
    @DisplayName("Key Generation: Should derive an AES key from a string password")
    void getKeyFromPassword_ValidKey() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("my-secret-password");

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        // PBKDF2 output was configured for 128 bits (16 bytes)
        assertEquals(16, key.getEncoded().length);
    }

    @Test
    @DisplayName("AES Encryption: Should produce consistent ciphertext (ECB Mode Property)")
    void encrypt_EcbDeterminism() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // In ECB mode, the same plaintext with the same key always produces the same ciphertext
        assertEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
    }

    @Test
    @DisplayName(
            "AES Encryption: Identical blocks should produce identical ciphertext blocks (ECB Vulnerability)")
    void encrypt_EcbPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // Split the ciphertext into two 16-byte segments
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, 0, block1, 0, 16);
        System.arraycopy(decoded, 16, block2, 0, 16);

        // The core vulnerability of ECB: identical input blocks = identical output blocks
        assertArrayEquals(block1, block2, "ECB mode failed to leak identical blocks");
    }

    @Test
    @DisplayName("HMAC-SHA256: Should produce consistent keyed hash")
    void hmacSha256_Consistent() throws EncryptionException {
        String data = "testPassword";
        String key = "externalizedSecretKey";

        String hmac1 = EncryptionUtils.hmacSha256(data, key);
        String hmac2 = EncryptionUtils.hmacSha256(data, key);

        assertNotNull(hmac1);
        assertEquals(hmac1, hmac2, "HMAC should be deterministic");
        assertEquals(64, hmac1.length(), "HMAC-SHA256 hex should be 64 characters");
    }

    @Test
    @DisplayName("HMAC-SHA256: Different keys should produce different results")
    void hmacSha256_DifferentKeys() throws EncryptionException {
        String data = "testPassword";

        String hmac1 = EncryptionUtils.hmacSha256(data, "key1");
        String hmac2 = EncryptionUtils.hmacSha256(data, "key2");

        assertNotEquals(hmac1, hmac2, "Different keys should produce different HMACs");
    }

    @Test
    @DisplayName("deriveShift: Should return a value between 1 and 25")
    void deriveShift_ValidRange() {
        int shift = EncryptionUtils.deriveShift("someSecretKey");

        assertTrue(shift >= 1 && shift <= 25, "Shift should be between 1 and 25");
    }

    @Test
    @DisplayName("deriveShift: Should be deterministic for the same key")
    void deriveShift_Deterministic() {
        int shift1 = EncryptionUtils.deriveShift("myKey");
        int shift2 = EncryptionUtils.deriveShift("myKey");

        assertEquals(shift1, shift2, "Same key should produce same shift");
    }

    @Test
    @DisplayName("Custom Cipher (keyed): Should produce consistent output with same key")
    void customCipher_Keyed_Consistent() throws EncryptionException {
        String input = "password";
        String key = "externalizedKey";

        String result1 = EncryptionUtils.customCipher(input, key);
        String result2 = EncryptionUtils.customCipher(input, key);

        assertNotNull(result1);
        assertEquals(result1, result2, "Same input and key should produce same output");
    }

    @Test
    @DisplayName("Custom Cipher (keyed): Different keys should produce different output")
    void customCipher_Keyed_DifferentKeys() throws EncryptionException {
        String input = "password";

        String result1 = EncryptionUtils.customCipher(input, "key1");
        String result2 = EncryptionUtils.customCipher(input, "key2");

        assertNotEquals(result1, result2, "Different keys should produce different ciphertexts");
    }
}
