package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.sasanlabs.internal.utility.exception.EncryptionException;

/** This class contains methods related to encryption. */
public class EncryptionUtils {

    private EncryptionUtils() {}

    /**
     * INSECURE: Caesar Cipher shifts alphabetic characters positions to the right overflowing to
     * the beginning of the alphabet. 'z' will shift to 'a' and so on.
     *
     * @param rawPassword plaintext password to encrypt
     * @param shift how many shifts right
     */
    public static String caesarCipher(String rawPassword, int shift) throws EncryptionException {

        if (rawPassword == null) {
            throw new EncryptionException("Raw password cannot be null ");
        }

        // Technically shift can be any non-zero integer, for clarity it should be between 0-25
        // inclusive
        if (shift < 0 || shift >= 26) {
            throw new EncryptionException("Shift value must be between 0 and 25 inclusive.");
        }

        StringBuilder builder = new StringBuilder();
        for (char ch : rawPassword.toCharArray()) {
            if (Character.isLetter(ch)) {
                char base = Character.isUpperCase(ch) ? 'A' : 'a';
                builder.append((char) ((ch - base + shift) % 26 + base));
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    /**
     * INSECURE: Custom cipher that obscures the texts by reversing it then Base64 encodes it.
     *
     * @param rawPassword password to encrypt
     */
    public static String customCipher(String rawPassword) throws EncryptionException {
        if (rawPassword == null) {
            throw new EncryptionException("Raw password cannot be null ");
        }
        String reversed = new StringBuilder(rawPassword).reverse().toString();
        return EncodingUtils.encodeBase64(reversed);
    }

    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int SALT_LENGTH = 16;

    public static SecretKey getKeyFromPassword(String password, byte[] salt)
            throws EncryptionException {
        try {
            if (salt == null || salt.length < SALT_LENGTH) {
                throw new EncryptionException("Salt must be at least " + SALT_LENGTH + " bytes");
            }
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 128);

            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Error generating AES key from password", e);
        }
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
        try {
            // Generate a cryptographically random nonce for each encryption operation
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Prepend nonce to ciphertext for self-contained output
            byte[] output = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, output, 0, nonce.length);
            System.arraycopy(encrypted, 0, output, nonce.length, encrypted.length);

            return java.util.Base64.getEncoder().encodeToString(output);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The provided key is invalid for AES encryption", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("Invalid GCM parameters for AES encryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES encryption failed due to block size or padding issues", e);
        }
    }

    public static String decrypt(String ciphertext, SecretKey key) throws EncryptionException {
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(ciphertext);

            if (decoded.length < GCM_NONCE_LENGTH) {
                throw new EncryptionException("Ciphertext too short to contain nonce");
            }

            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            System.arraycopy(decoded, 0, nonce, 0, GCM_NONCE_LENGTH);

            byte[] encrypted = new byte[decoded.length - GCM_NONCE_LENGTH];
            System.arraycopy(decoded, GCM_NONCE_LENGTH, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The provided key is invalid for AES decryption", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("Invalid GCM parameters for AES decryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES decryption failed due to block size or padding issues", e);
        }
    }

    public static String encryptWithPassword(String plaintext, String password)
            throws EncryptionException {
        byte[] salt = generateSalt();
        SecretKey key = getKeyFromPassword(password, salt);
        String encrypted = encrypt(plaintext, key);
        byte[] encBytes = java.util.Base64.getDecoder().decode(encrypted);
        byte[] output = new byte[SALT_LENGTH + encBytes.length];
        System.arraycopy(salt, 0, output, 0, SALT_LENGTH);
        System.arraycopy(encBytes, 0, output, SALT_LENGTH, encBytes.length);
        return java.util.Base64.getEncoder().encodeToString(output);
    }

    public static String decryptWithPassword(String ciphertext, String password)
            throws EncryptionException {
        byte[] decoded = java.util.Base64.getDecoder().decode(ciphertext);
        if (decoded.length < SALT_LENGTH + GCM_NONCE_LENGTH) {
            throw new EncryptionException("Ciphertext too short to contain salt and nonce");
        }
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(decoded, 0, salt, 0, SALT_LENGTH);
        byte[] encBytes = new byte[decoded.length - SALT_LENGTH];
        System.arraycopy(decoded, SALT_LENGTH, encBytes, 0, encBytes.length);
        SecretKey key = getKeyFromPassword(password, salt);
        return decrypt(java.util.Base64.getEncoder().encodeToString(encBytes), key);
    }
}
