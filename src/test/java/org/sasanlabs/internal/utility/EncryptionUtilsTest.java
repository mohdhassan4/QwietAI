package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.sasanlabs.internal.utility.exception.EncryptionException;

class EncryptionUtilsTest {

    /** Length of the AES-GCM nonce that {@code EncryptionUtils} prepends to every ciphertext. */
    private static final int GCM_NONCE_LENGTH = 12;

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
    @DisplayName("AES-GCM Encryption: A fresh nonce should make every ciphertext unique")
    void encrypt_UsesFreshNoncePerInvocation() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // A randomized nonce means the same plaintext and key never repeat a ciphertext
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64 and that both ciphertexts still recover the plaintext
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext1, key));
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext2, key));
    }

    @Test
    @DisplayName("AES-GCM Encryption: Identical plaintext blocks must not leak")
    void encrypt_DoesNotLeakIdenticalBlocks() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("no-pattern-leakage");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // Layout is: 12-byte GCM nonce || ciphertext || 16-byte authentication tag
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, GCM_NONCE_LENGTH, block1, 0, 16);
        System.arraycopy(decoded, GCM_NONCE_LENGTH + 16, block2, 0, 16);

        // Unlike ECB, identical input blocks must not produce identical output blocks
        assertNotEquals(
                EncodingUtils.bytesToHex(block1),
                EncodingUtils.bytesToHex(block2),
                "Identical plaintext blocks leaked into identical ciphertext blocks");
    }

    @Test
    @DisplayName("AES-GCM Decryption: Round trip should recover the original plaintext")
    void decrypt_RoundTrip() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("round-trip");
        String plaintext = "correct horse battery staple";

        assertEquals(
                plaintext, EncryptionUtils.decrypt(EncryptionUtils.encrypt(plaintext, key), key));
    }

    @Test
    @DisplayName("AES-GCM Decryption: A wrong key should fail the authentication tag check")
    void decrypt_WrongKeyIsRejected() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("right-key");
        SecretKey other = EncryptionUtils.getKeyFromPassword("wrong-key");
        String ciphertext = EncryptionUtils.encrypt("secret", key);

        assertThrows(EncryptionException.class, () -> EncryptionUtils.decrypt(ciphertext, other));
    }

    @Test
    @DisplayName("AES-GCM Decryption: A tampered ciphertext should be rejected")
    void decrypt_TamperedCiphertextIsRejected() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("integrity");
        byte[] decoded = Base64.getDecoder().decode(EncryptionUtils.encrypt("transfer 10", key));

        // Flip a single bit in the ciphertext body
        decoded[GCM_NONCE_LENGTH] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(decoded);

        assertThrows(EncryptionException.class, () -> EncryptionUtils.decrypt(tampered, key));
    }
}
