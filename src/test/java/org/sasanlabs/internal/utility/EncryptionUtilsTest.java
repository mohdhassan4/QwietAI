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
    @DisplayName(
            "AES GCM Encryption: Should produce different ciphertext for each invocation"
                    + " (random IV)")
    void encrypt_GcmNonDeterminism() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // GCM with random IV produces different ciphertext each time
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
    }

    @Test
    @DisplayName("AES GCM Encryption: Ciphertext should include 12-byte IV prefix")
    void encrypt_GcmCiphertextContainsIv() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("iv-test-password");
        String plaintext = "short";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // IV (12 bytes) + ciphertext (plaintext length) + GCM auth tag (16 bytes)
        assertTrue(
                decoded.length >= 12 + plaintext.length() + 16,
                "Ciphertext should contain IV + encrypted data + auth tag");
    }

    @Test
    @DisplayName("AES GCM Decryption: Should correctly round-trip encrypt then decrypt")
    void decrypt_RoundTrip() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("round-trip-password");
        String plaintext = "Hello, World! This is a test of AES-GCM encryption.";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        String decrypted = EncryptionUtils.decrypt(ciphertext, key);

        assertEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("AES GCM Decryption: Should fail with wrong key")
    void decrypt_WrongKeyFails() throws EncryptionException {
        SecretKey encryptKey = EncryptionUtils.getKeyFromPassword("correct-password");
        SecretKey wrongKey = EncryptionUtils.getKeyFromPassword("wrong-password");
        String plaintext = "secret data";

        String ciphertext = EncryptionUtils.encrypt(plaintext, encryptKey);

        assertThrows(EncryptionException.class, () -> EncryptionUtils.decrypt(ciphertext, wrongKey));
    }

    @Test
    @DisplayName(
            "AES GCM: Identical plaintext blocks should NOT produce identical ciphertext blocks")
    void encrypt_GcmNoPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // Skip the 12-byte IV, then compare two 16-byte segments
        // With GCM, identical plaintext blocks produce different ciphertext blocks
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, 12, block1, 0, 16);
        System.arraycopy(decoded, 28, block2, 0, 16);

        assertFalse(
                java.util.Arrays.equals(block1, block2),
                "GCM mode should not leak block patterns");
    }
}
