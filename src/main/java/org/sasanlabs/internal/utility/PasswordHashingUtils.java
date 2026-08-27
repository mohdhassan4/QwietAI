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
    private static final int SALT_LENGTH = 16;
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

    /**
     * Computes a salted hash with a random 16-byte salt. Returns the result as {@code
     * hexSalt:hexHash}.
     */
    public static String getHashAsHex(String rawPassword, HashAlgorithm hashAlgorithm) {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return getHashAsHex(rawPassword, hashAlgorithm, salt);
    }

    /**
     * Computes a salted hash with the provided salt. Returns the result as {@code
     * hexSalt:hexHash}.
     */
    public static String getHashAsHex(
            String rawPassword, HashAlgorithm hashAlgorithm, byte[] salt) {
        byte[] digest =
                computeDigest(salt, rawPassword.getBytes(StandardCharsets.UTF_8), hashAlgorithm);
        return EncodingUtils.bytesToHex(salt) + HASH_SEPARATOR + EncodingUtils.bytesToHex(digest);
    }

    /**
     * Verifies a raw password against a stored salted hash in {@code hexSalt:hexHash} format.
     */
    public static boolean verifyHashHex(
            String rawPassword, String storedSaltedHash, HashAlgorithm hashAlgorithm) {
        if (rawPassword == null || storedSaltedHash == null) {
            return false;
        }
        String[] parts = storedSaltedHash.split(HASH_SEPARATOR, 2);
        if (parts.length != 2) {
            return false;
        }
        byte[] salt = EncodingUtils.hexToBytes(parts[0]);
        byte[] digest =
                computeDigest(salt, rawPassword.getBytes(StandardCharsets.UTF_8), hashAlgorithm);
        return parts[1].equalsIgnoreCase(EncodingUtils.bytesToHex(digest));
    }

    private static byte[] computeDigest(byte[] salt, byte[] input, HashAlgorithm hashAlgorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.label(), "BC");
            messageDigest.update(salt);
            return messageDigest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(hashAlgorithm + " Hash Algorithm Not Found", e);
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

    /**
     * Computes SHA-256 of salt concatenated with the raw password. The salt is treated as a UTF-8
     * string prefix. Returns only the hex digest (not the salt:hash format).
     */
    public static String sha256Hex(String salt, String rawPassword) {
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        byte[] digest =
                computeDigest(
                        saltBytes,
                        rawPassword.getBytes(StandardCharsets.UTF_8),
                        HashAlgorithm.SHA256);
        return EncodingUtils.bytesToHex(digest);
    }

    /**
     * Computes a salted SHA-256 hash with a random salt. Returns {@code hexSalt:hexHash}.
     *
     * <p>Despite the legacy name, this method now generates a random salt to prevent rainbow table
     * attacks.
     */
    public static String unsaltedSha256Hex(String rawPassword) {
        return getHashAsHex(rawPassword, HashAlgorithm.SHA256);
    }

    public static boolean verifyMd4Hex(String rawPassword, String storedSaltedHash) {
        return verifyHashHex(rawPassword, storedSaltedHash, HashAlgorithm.MD4);
    }

    public static boolean verifyMd5Hex(String rawPassword, String storedSaltedHash) {
        return verifyHashHex(rawPassword, storedSaltedHash, HashAlgorithm.MD5);
    }

    public static boolean verifySha1Hex(String rawPassword, String storedSaltedHash) {
        return verifyHashHex(rawPassword, storedSaltedHash, HashAlgorithm.SHA1);
    }

    public static boolean verifySha256Hex(String rawPassword, String storedSaltedHash) {
        return verifyHashHex(rawPassword, storedSaltedHash, HashAlgorithm.SHA256);
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
            return EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey1))
                    + EncodingUtils.bytesToHex(lmAesEncrypt(tmpKey2));
        } catch (Exception e) {
            throw new RuntimeException("LM Hashing failed", e);
        }
    }

    private static byte[] lmAesEncrypt(byte[] key7) throws Exception {
        // Derive a 32-byte value from the 7-byte password material using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "BC");
        byte[] derived = sha256.digest(key7);

        // Use first 16 bytes as AES-128 key
        byte[] aesKey = new byte[16];
        System.arraycopy(derived, 0, aesKey, 0, 16);

        // Use bytes 16-27 as the GCM nonce (12 bytes); deterministic per unique key input
        byte[] nonce = new byte[12];
        System.arraycopy(derived, 16, nonce, 0, 12);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), gcmSpec);
        return aes.doFinal("KGS!@#$%".getBytes(StandardCharsets.US_ASCII));
    }
}
