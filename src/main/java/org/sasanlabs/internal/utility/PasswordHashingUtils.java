package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;

    /** Fixed salt for LM key derivation via PBKDF2 (deterministic, same input same output). */
    private static final byte[] LM_KDF_SALT = {
        (byte) 0x4c, (byte) 0x4d, (byte) 0x2d, (byte) 0x6b,
        (byte) 0x64, (byte) 0x66, (byte) 0x2d, (byte) 0x73,
        (byte) 0x61, (byte) 0x6c, (byte) 0x74, (byte) 0x2d,
        (byte) 0x76, (byte) 0x31, (byte) 0x30, (byte) 0x30
    };

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
     * Computes an LM hash for the given password.
     *
     * <p>Algorithm based on the LAN Manager specification.
     *
     * @see <a href="https://en.wikipedia.org/wiki/LAN_Manager">Wikipedia: LAN Manager</a>
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

            // Encrypt the magic string "KGS!@#$%" using each key
            return EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmDesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmDesEncrypt(byte[] key7) throws Exception {
        // Convert key7 to char[] for PBKDF2 input
        char[] keyChars = new char[key7.length];
        for (int i = 0; i < key7.length; i++) {
            keyChars[i] = (char) (key7[i] & 0xFF);
        }

        // Derive 256-bit AES key + 96-bit GCM nonce using PBKDF2 with a fixed salt
        SecretKeyFactory kdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec keySpec = new PBEKeySpec(keyChars, LM_KDF_SALT, 1000, 256 + 96);
        byte[] derivedBytes = kdf.generateSecret(keySpec).getEncoded();
        keySpec.clearPassword();

        byte[] aesKeyBytes = new byte[32];
        System.arraycopy(derivedBytes, 0, aesKeyBytes, 0, 32);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        byte[] nonce = new byte[12];
        System.arraycopy(derivedBytes, 32, nonce, 0, 12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        return cipher.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
