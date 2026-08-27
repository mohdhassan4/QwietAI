package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final Logger LOGGER = LogManager.getLogger(PasswordHashingUtils.class);
    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;

    private PasswordHashingUtils() {}

    // Available Hashing Algorithms
    public enum HashAlgorithm {
        MD4("MD4"),
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256");

        private final String algorithmName;

        HashAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        public String label() {
            return this.algorithmName;
        }
    }

    // Registers Bouncy Castle as provider
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String md4Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD4);
    }

    public static String md5Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.MD5);
    }

    public static String sha1Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA1);
    }

    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Hash algorithm not found: {}", hashAlgorithm, e);
            throw new IllegalStateException(hashAlgorithm + " Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            LOGGER.error("Security provider Bouncy Castle not found", e);
            throw new IllegalStateException("Security Provider Bouncy Castle not found", e);
        }
    }

    public static boolean isValidSaltedSha256(String rawPassword, String saltedSha256Hash) {
        if (saltedSha256Hash == null || rawPassword == null) {
            return false;
        }

        String[] saltAndHash = saltedSha256Hash.split(HASH_SEPARATOR, 2);
        if (saltAndHash.length != 2) {
            // Backward compatibility for old plaintext test data.
            return saltedSha256Hash.equals(rawPassword);
        }

        String calculatedHash = sha256Hex(saltAndHash[0], rawPassword);
        return saltAndHash[1].equalsIgnoreCase(calculatedHash);
    }

    public static String sha256Hex(String salt, String rawPassword) {
        return getHashAsHex(salt + rawPassword, HashAlgorithm.SHA256);
    }

    public static String unsaltedSha256Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256);
    }

    // BC not used for bcrypt due to extra complexity for BC implementation
    public static int getbcryptWorkFactor() {
        return bcryptWorkFactor;
    }

    public static String bCryptHash(String rawPassword) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.encode(rawPassword);
    }

    public static boolean isValidBcrypt(String rawPassword, String bcryptHash) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(bcryptWorkFactor);
        return encoder.matches(rawPassword, bcryptHash);
    }

    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    /**
     * Encrypts data using AES-256-GCM. The returned byte array contains the IV (first 12 bytes)
     * followed by the ciphertext+tag.
     *
     * @param key a 256-bit (32-byte) AES key
     * @param plaintext data to encrypt
     * @return IV || ciphertext || authentication tag
     */
    public static byte[] aesGcmEncrypt(SecretKey key, byte[] plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM, "BC");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            byte[] ciphertext = cipher.doFinal(plaintext);

            // Prepend IV to ciphertext
            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts data encrypted with {@link #aesGcmEncrypt(SecretKey, byte[])}. Expects IV (first 12
     * bytes) followed by ciphertext+tag.
     *
     * @param key the same 256-bit AES key used for encryption
     * @param ivAndCiphertext the IV || ciphertext || tag produced by aesGcmEncrypt
     * @return the decrypted plaintext
     */
    public static byte[] aesGcmDecrypt(SecretKey key, byte[] ivAndCiphertext) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);

            byte[] ciphertext = new byte[ivAndCiphertext.length - iv.length];
            System.arraycopy(ivAndCiphertext, iv.length, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM, "BC");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }

    /**
     * Generates a new random AES-256 secret key suitable for use with {@link
     * #aesGcmEncrypt(SecretKey, byte[])}.
     */
    public static SecretKey generateAesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(AES_KEY_SIZE_BITS, new SecureRandom());
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("AES key generation failed", e);
        }
    }

    /**
     * Computes an LM hash for the given password.
     *
     * <p>Algorithm based on the LAN Manager specification.
     *
     * @deprecated LM hash uses DES which is cryptographically weak. This method is retained solely
     *     for legacy LAN Manager protocol compatibility. Use {@link #aesGcmEncrypt(SecretKey,
     *     byte[])} for general-purpose encryption.
     * @see <a href="https://en.wikipedia.org/wiki/LAN_Manager">Wikipedia: LAN Manager</a>
     */
    @Deprecated
    public static String lmHash(String rawPassword) {
        try {
            // Convert to uppercase and pad to 14 bytes
            String pwd = rawPassword.toUpperCase();
            byte[] keyBytes = new byte[14];
            byte[] passwordBytes = pwd.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, 14));

            // Split into two 7-byte keys
            byte[] tmpKey1 = new byte[7];
            byte[] tmpKey2 = new byte[7];
            System.arraycopy(keyBytes, 0, tmpKey1, 0, 7);
            System.arraycopy(keyBytes, 7, tmpKey2, 0, 7);

            // Encrypt the magic string "KGS!@#$%" using each key
            return EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    /**
     * LM protocol DES step: turns 7-byte key material into an 8-byte DES key and encrypts the
     * magic constant. Retained for LAN Manager protocol compatibility only.
     *
     * @deprecated Uses DES (56-bit), which is cryptographically broken. Use {@link
     *     #aesGcmEncrypt(SecretKey, byte[])} for any new encryption needs.
     */
    @Deprecated
    private static byte[] lmDesEncrypt(byte[] key7) throws Exception {
        // LM Hash uses a specific parity-bit transformation to turn 7 bytes into an 8-byte DES key
        byte[] key8 = new byte[8];
        key8[0] = (byte) (key7[0] >> 1);
        key8[1] = (byte) (((key7[0] & 0x01) << 6) | (key7[1] >> 2));
        key8[2] = (byte) (((key7[1] & 0x03) << 5) | (key7[2] >> 3));
        key8[3] = (byte) (((key7[2] & 0x07) << 4) | (key7[3] >> 4));
        key8[4] = (byte) (((key7[3] & 0x0F) << 3) | (key7[4] >> 5));
        key8[5] = (byte) (((key7[4] & 0x1F) << 2) | (key7[5] >> 6));
        key8[6] = (byte) (((key7[5] & 0x3F) << 1) | (key7[6] >> 7));
        key8[7] = (byte) (key7[6] & 0x7F);

        for (int i = 0; i < 8; i++) {
            key8[i] = (byte) (key8[i] << 1);
        }

        // DES is required by the LM hash protocol specification (RFC / MS-NLMP).
        // For general-purpose encryption use aesGcmEncrypt() instead.
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key8, "DES"));
        return cipher.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
