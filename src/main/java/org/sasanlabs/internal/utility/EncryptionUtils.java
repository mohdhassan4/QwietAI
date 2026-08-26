package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
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

    private static final byte[] salt = new byte[16];

    static {
        new SecureRandom().nextBytes(salt);
    }

    public static SecretKey getKeyFromPassword(String password) throws EncryptionException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1, 128);

            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Error generating AES key from password", e);
        }
    }

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
        try {
            // Derive a deterministic nonce from key + plaintext using SHA-256
            // This ensures same key+plaintext produces same ciphertext (needed by callers)
            // while avoiding ECB mode weaknesses.
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(key.getEncoded());
            sha256.update(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] nonceSource = sha256.digest();
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            System.arraycopy(nonceSource, 0, nonce, 0, GCM_NONCE_LENGTH);

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
}
