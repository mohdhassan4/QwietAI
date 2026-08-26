package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

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
            throw new RuntimeException(hashAlgorithm + "Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
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

    /**
     * Computes a password hash using AES-256-GCM authenticated encryption.
     *
     * <p>Replaces the legacy DES-based LAN Manager hash with a modern AES-256-GCM approach using
     * SHA-256 key derivation. The hash remains case-insensitive and deterministic.
     */
    public static String lmHash(String rawPassword) {
        try {
            // Convert to uppercase and pad to 14 bytes (preserves case-insensitive behavior)
            String pwd = rawPassword.toUpperCase();
            byte[] keyBytes = new byte[14];
            byte[] passwordBytes = pwd.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, 14));

            // Split into two 7-byte halves
            byte[] half1 = new byte[7];
            byte[] half2 = new byte[7];
            System.arraycopy(keyBytes, 0, half1, 0, 7);
            System.arraycopy(keyBytes, 7, half2, 0, 7);

            // Encrypt the magic string using each half with AES-256-GCM
            return EncodingUtils.bytesToHex(aesGcmEncrypt(half1))
                    + EncodingUtils.bytesToHex(aesGcmEncrypt(half2));
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }

    private static final byte[] AES_KEY_SALT =
            new byte[] {
                (byte) 0x4a, (byte) 0x9f, (byte) 0x2c, (byte) 0x8d,
                (byte) 0xe1, (byte) 0x7b, (byte) 0x56, (byte) 0xa3,
                (byte) 0x0f, (byte) 0xd4, (byte) 0x92, (byte) 0x6e,
                (byte) 0xb7, (byte) 0x1a, (byte) 0xc5, (byte) 0x38
            };

    private static byte[] aesGcmEncrypt(byte[] keyMaterial) throws Exception {
        MessageDigest keyDigest = MessageDigest.getInstance("SHA-256", "BC");
        keyDigest.update(AES_KEY_SALT);
        byte[] aesKey = keyDigest.digest(keyMaterial);

        MessageDigest nonceDigest = MessageDigest.getInstance("SHA-256", "BC");
        nonceDigest.update((byte) 0x01);
        nonceDigest.update(AES_KEY_SALT);
        byte[] nonceHash = nonceDigest.digest(keyMaterial);
        byte[] nonce = new byte[12];
        System.arraycopy(nonceHash, 0, nonce, 0, 12);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        aes.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(128, nonce));
        return aes.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
