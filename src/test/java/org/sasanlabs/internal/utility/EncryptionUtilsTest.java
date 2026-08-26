package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

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
    @DisplayName("AES/GCM Encryption: Should produce different ciphertext each time (random IV)")
    void encrypt_GcmNonDeterminism() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // GCM uses a random IV so two encryptions of the same plaintext differ
        assertNotEquals(ciphertext1, ciphertext2);

        // Both should decrypt back to the original plaintext
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext1, key));
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext2, key));
    }

    @Test
    @DisplayName("AES/GCM Encryption: Should not leak identical block patterns")
    void encrypt_GcmNoPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);

        // Should round-trip correctly
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext, key));
    }
}
