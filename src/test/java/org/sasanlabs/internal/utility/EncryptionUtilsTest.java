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
    @DisplayName("AES-GCM Encryption: Each encryption produces unique ciphertext (random IV)")
    void encrypt_GcmNonDeterminism() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // GCM uses a random IV so the same plaintext+key produces different ciphertext each time
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify both are valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext2));
    }

    @Test
    @DisplayName("AES-GCM Encryption: Ciphertext can be decrypted back to original plaintext")
    void encrypt_GcmRoundTrip() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("round-trip-test");
        String plaintext = "Sensitive data to encrypt and decrypt";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        String decrypted = EncryptionUtils.decrypt(ciphertext, key);

        assertEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName(
            "AES-GCM Encryption: Identical plaintext blocks do NOT produce identical ciphertext"
                    + " blocks (GCM prevents pattern leakage)")
    void encrypt_GcmNoPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // GCM output: 12-byte IV + ciphertext + 16-byte auth tag
        // Skip IV (first 12 bytes), compare first two 16-byte ciphertext blocks
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, 12, block1, 0, 16);
        System.arraycopy(decoded, 28, block2, 0, 16);

        // GCM mode: identical input blocks produce DIFFERENT output blocks (no pattern leakage)
        assertFalse(
                java.util.Arrays.equals(block1, block2),
                "GCM should not produce identical output blocks for identical input blocks");
    }
}
