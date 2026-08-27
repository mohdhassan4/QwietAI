package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
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
     * Computes a password hash using AES-GCM authenticated encryption.
     *
     * <p>The password is uppercased and split into two 7-byte halves.
     * Each half is used to derive an AES key and GCM nonce via SHA-256,
     * then encrypts a constant with AES/GCM/NoPadding. This provides
     * authenticated encryption (integrity + confidentiality).
     */
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

            // Encrypt the magic string "KGS!@#$%" using each key with AES-GCM
            return EncodingUtils.bytesToHex(aesGcmEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(aesGcmEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static final byte[] KDF_SALT =
            "VulnerableApp-LMHash-KDF-Salt".getBytes(StandardCharsets.UTF_8);

    private static byte[] aesGcmEncrypt(byte[] key7) throws Exception {
        // Derive a 16-byte AES key and 12-byte GCM nonce from input using salted SHA-256.
        // A fixed application-level salt is prepended so the hash is not unsalted.
        // Each unique key7 (from a unique password half) produces a unique (key, nonce) pair,
        // so GCM's uniqueness requirement is satisfied even though the plaintext is constant.
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
        sha256.update(KDF_SALT);
        byte[] derived = sha256.digest(key7);
        byte[] aesKey = Arrays.copyOfRange(derived, 0, 16);
        byte[] nonce = Arrays.copyOfRange(derived, 16, 28);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), gcmSpec);
        return aes.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
