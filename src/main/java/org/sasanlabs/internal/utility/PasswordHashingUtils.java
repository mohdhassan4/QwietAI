package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int SALT_LENGTH_BYTES = 16;

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

    /**
     * Generates a random salt and hashes the password with that salt. Returns the result in the
     * format {@code saltHex:hashHex} so the salt is stored alongside the hash.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = generateSalt();
        String hash = getHashAsHex(rawPassword, salt, hashAlgorithm);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + hash;
    }

    /**
     * Hashes the password with the provided salt bytes. The salt is fed to the digest via {@code
     * update()} before the password bytes. Returns only the hash hex (caller manages salt storage).
     */
    public static String getHashAsHex(
            String rawPassword, byte[] salt, HashAlgorithm hashAlgorithm) {
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt must not be null or empty");
        }
        try {
            MessageDigest messageDigest =
                    MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest =
                    messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + " Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Verifies a password against a stored salted hash in the format {@code saltHex:hashHex}.
     * Returns false if the format is invalid or the password does not match.
     */
    public static boolean verifySaltedHash(
            String rawPassword, String storedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        String[] parts = storedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computedHash = getHashAsHex(rawPassword, salt, hashAlgorithm);
        return MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.UTF_8),
                parts[1].getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
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

        byte[] saltBytes = saltAndHash[0].getBytes(StandardCharsets.UTF_8);
        String calculatedHash = getHashAsHex(rawPassword, saltBytes, HashAlgorithm.SHA256);
        return MessageDigest.isEqual(
                calculatedHash.getBytes(StandardCharsets.UTF_8),
                saltAndHash[1].getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(String salt, String rawPassword) {
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        return getHashAsHex(rawPassword, saltBytes, HashAlgorithm.SHA256);
    }

    public static String sha256HexWithRandomSalt(String rawPassword) {
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
            return EncodingUtils.bytesToHex(lmEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmEncrypt(byte[] key7) throws Exception {
        // Original LM Hash parity-bit transformation to turn 7 bytes into 8-byte key material.
        // Note: The legacy LM hash algorithm used DES/ECB which is cryptographically broken
        // (56-bit effective key, vulnerable to brute-force). This implementation replaces DES
        // with AES-256/CBC to provide a secure encryption step while preserving the overall
        // LM-style hash structure. This breaks wire compatibility with legacy LAN Manager
        // but provides a secure deterministic hash for this application's purposes.
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

        // Derive AES-256 key from key material using salted SHA-256 (deterministic key derivation)
        MessageDigest keyDigest = MessageDigest.getInstance("SHA-256", "BC");
        keyDigest.update("lm-aes-key-derivation".getBytes(StandardCharsets.UTF_8));
        byte[] aesKeyBytes = keyDigest.digest(key8);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Derive a deterministic IV from key material using a domain-separated SHA-256
        MessageDigest ivDigest = MessageDigest.getInstance("SHA-256", "BC");
        ivDigest.update((byte) 0x01); // domain separator to avoid key/IV collision
        byte[] ivFull = ivDigest.digest(key8);
        byte[] iv = new byte[16];
        System.arraycopy(ivFull, 0, iv, 0, 16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Pad the LM magic constant to AES block size (16 bytes)
        byte[] magic = "KGS!@#$%".getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = new byte[16];
        System.arraycopy(magic, 0, plaintext, 0, magic.length);

        // Encrypt with AES-256/CBC
        Cipher aes = Cipher.getInstance("AES/CBC/NoPadding", "BC");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] ciphertext = aes.doFinal(plaintext);

        // Return first 8 bytes to maintain hash-length compatibility with LM format
        byte[] result = new byte[8];
        System.arraycopy(ciphertext, 0, result, 0, 8);
        return result;
    }
}
