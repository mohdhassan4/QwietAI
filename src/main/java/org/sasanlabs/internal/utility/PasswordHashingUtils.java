package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Utility class for various password hashing algorithms. */
public final class PasswordHashingUtils {

    private static final String HASH_SEPARATOR = ":";
    private static final int bcryptWorkFactor = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int SALT_LENGTH = 16;

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

    /**
     * Generates a salted MD4 hash. Returns hex(salt):hex(hash).
     *
     * <p>Note: MD4 is a weak algorithm retained for vulnerability demonstration purposes.
     */
    public static String md4Hex(String rawPassword) {
        return saltedHashAsHex(rawPassword, HashAlgorithm.MD4);
    }

    /**
     * Generates a salted MD5 hash. Returns hex(salt):hex(hash).
     *
     * <p>Note: MD5 is a weak algorithm retained for vulnerability demonstration purposes.
     */
    public static String md5Hex(String rawPassword) {
        return saltedHashAsHex(rawPassword, HashAlgorithm.MD5);
    }

    /**
     * Generates a salted SHA-1 hash. Returns hex(salt):hex(hash).
     *
     * <p>Note: SHA-1 is a weak algorithm retained for vulnerability demonstration purposes.
     */
    public static String sha1Hex(String rawPassword) {
        return saltedHashAsHex(rawPassword, HashAlgorithm.SHA1);
    }

    /**
     * Computes a hash with the provided salt. The salt bytes are fed into the digest before the
     * password bytes to prevent rainbow table attacks.
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return EncodingUtils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + "Hash Algorithm Not Found", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Security Provider Bouncy Castle not found", e);
        }
    }

    /**
     * Generates a random salt and computes a salted hash. Returns the result in the format
     * hex(salt):hex(hash).
     */
    public static String saltedHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = generateSalt();
        String hash = getHashAsHex(rawPassword, hashAlgorithm, salt);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + hash;
    }

    /** Verifies a password against a stored salted hash in the format hex(salt):hex(hash). */
    public static boolean isValidSaltedHash(
            String rawPassword, String storedSaltedHash, HashAlgorithm algorithm) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        String computedHash = getHashAsHex(rawPassword, algorithm, salt);
        return MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.UTF_8),
                parts[1].toLowerCase().getBytes(StandardCharsets.UTF_8));
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
        return getHashAsHex(
                rawPassword, HashAlgorithm.SHA256, salt.getBytes(StandardCharsets.UTF_8));
    }

    /** Generates a salted SHA-256 hash. Returns hex(salt):hex(hash). */
    public static String saltedSha256Hex(String rawPassword) {
        return saltedHashAsHex(rawPassword, HashAlgorithm.SHA256);
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
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

        Cipher des = Cipher.getInstance("DES/ECB/NoPadding", "BC");
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key8, "DES"));
        return des.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
